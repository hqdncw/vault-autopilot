import asyncio
import itertools
import logging
import pathlib
from typing import IO, Iterator, NoReturn

import click

from .. import conf, dispatcher, exc, pipeline, service
from .._pkg import asyva

logger = logging.getLogger(__name__)

FilenamesOption = list[str]


def read_files(
    filenames: Iterator[pathlib.Path], pass_stdin: bool = False
) -> Iterator[IO[bytes]]:
    """
    If `pass_stdin` is True, ignores the provided file paths and reads the contents of
    STDIN instead. Otherwise, opens each file path in binary mode using `open()` and
    yields its contents as an iterator.

    Args:
        filenames (Iterator[pathlib.Path]): An iterator of file paths to read from.
        pass_stdin (bool): Whether to read from STDIN instead of the file paths.

    Returns:
        An iterator of I/O objects.
    """
    if pass_stdin:
        logger.debug("streaming manifests from stdin")
        yield click.get_binary_stream(name="stdin")
    else:
        for fn in filenames:
            logger.debug("streaming file %r" % fn)
            yield open(fn, "rb")


def resolve_file(
    fn: pathlib.Path, suffix: str, recursive: bool = False
) -> Iterator[pathlib.Path]:
    """
    Yields absolute file paths matching the given suffix.

    Args:
        fn (pathlib.Path): The file path to resolve
        suffix (str): The suffix to filter by
        recursive (bool, optional): Recursively search directories, defaults to `False`

    Returns:
        An iterator of absolute file paths that exist in the file system and have the
        specified suffix.

    Details:
        If a directory, recursively searches for files with the specified suffix if
        `recursive` is `True`.
    """
    fn.stat()
    pattern = "*%s" % suffix
    for fn in filter(
        lambda fn: fn.is_file() and fn.stat(),
        fn.rglob(pattern)
        if recursive
        else ((fn,) if fn.is_file() else fn.glob(pattern)),
    ):
        yield fn.absolute()


def gather_files(filenames: FilenamesOption, recursive: bool) -> Iterator[pathlib.Path]:
    """Gathers all manifests found in the given file paths."""
    for path in map(pathlib.Path, filenames):
        logger.debug("resolving %r" % path)

        if path.is_file():
            iter = resolve_file(path, suffix="", recursive=False)
        else:
            iter = itertools.chain(
                resolve_file(path, suffix=".yaml", recursive=recursive),
                resolve_file(path, suffix=".yml", recursive=recursive),
            )

        for fn in iter:
            logger.debug("discovered file %r" % fn)
            yield fn


def stdin_has_data(filenames: FilenamesOption) -> bool:
    """Returns `True` if user requested the program to read from stdin, `False`
    otherwise."""
    res = any(val == "-" for val in filenames) if filenames else False
    return res


async def parse_files(
    filenames: FilenamesOption,
    queue: asyncio.PriorityQueue[dispatcher.PrioritizedItem],
    stdin_nonempty: bool,
    recursive: bool,
) -> None:
    await pipeline.YamlPipeline(
        queue=queue,
        streamer=read_files(
            filenames=gather_files(filenames, recursive),
            pass_stdin=stdin_nonempty,
        ),
    ).execute()


def raise_unexpected_err(ex: Exception) -> NoReturn:
    logger.critical(ex, exc_info=ex)
    raise exc.ApplicationError("Unexpected error: %s" % ex) from ex


async def async_apply(
    settings: conf.Settings,
    client: asyva.Client,
    filenames: FilenamesOption,
    recursive: bool,
) -> None:
    authn = settings.auth.get_authenticator()

    if stdin_nonempty := stdin_has_data(filenames=filenames):
        if filenames and len(filenames) > 1:
            raise exc.StdinInputCombinationError(
                "Cannot combine stdin with filenames (-f)"
            )

    queue: pipeline.QueueType = asyncio.PriorityQueue()

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                client.authenticate(
                    base_url=settings.base_url,
                    authn=authn,
                    namespace=settings.namespace,
                )
            )
            tg.create_task(
                parse_files(
                    filenames=filenames,
                    queue=queue,
                    stdin_nonempty=bool(stdin_nonempty),
                    recursive=recursive,
                )
            )
    except ExceptionGroup as eg:
        ex = eg.exceptions[0]

        if isinstance(
            ex, (asyva.exc.ConnectionRefusedError, asyva.exc.AuthenticationError)
        ):
            logger.debug(ex, exc_info=ex)
            raise exc.ApplicationError("Authentication error: %s" % ex) from ex
        elif isinstance(ex, exc.ManifestValidationError):
            raise ex
        elif isinstance(ex, FileNotFoundError):
            raise exc.ApplicationError(str(ex))
        else:
            raise_unexpected_err(ex)
    except Exception as e:
        raise_unexpected_err(e)
    else:
        # TODO: make the pipeline implementation coroutine-safe, so that we can run the
        # dispatcher concurrently.
        try:
            await dispatcher.Dispatcher(
                passwd_svc=service.PasswordService(client=client),
                queue=queue,
            ).dispatch()
        except ExceptionGroup as eg:
            ex = eg.exceptions[0]

            if isinstance(ex, asyva.exc.CASParameterMismatchError):
                # TODO: print the contents of a YAML file, highlighting any invalid
                #  lines.
                raise ex
            else:
                raise_unexpected_err(ex)
        except Exception as ex:
            raise_unexpected_err(ex)

        click.secho("Thanks for choosing Vault Autopilot!", fg="yellow")


# TODO: epilog https://click.palletsprojects.com/en/8.1.x/documentation/#command-epilog-help
# TODO: ca-cert, ca-path, client-cert, client-key
@click.command()
@click.option(
    "-f",
    "--filename",
    multiple=True,
    required=True,
    help="The manifest to apply",
)
@click.option(
    "-R",
    "--recursive",
    is_flag=True,
    default=False,
    help=(
        "Process the directory used in `-f`, `--filename` recursively. Useful when you "
        "want to manage related manifests organized within the same directory"
    ),
)
@click.pass_context
def apply(ctx: click.Context, filename: FilenamesOption, recursive: bool) -> None:
    """
    Apply a manifest to a Vault server by file name or stdin.

    Manifest Format:

    \b
      A manifest is a YAML file that defines one or more resources to create,
      update, or delete on a Vault server. Each resource has a kind, metadata,
      and spec field.

    Examples:

    \b
      # Apply a single manifest from a file
      $ vault-autopilot apply -f manifest.yaml
    \b
      # Apply all manifests recursively
      $ vault-autopilot apply -Rf /path/to/folder
    \b
      # Pipe the contents of a file to standard input
      $ cat manifest.yaml | vault-autopilot apply -f -
    """
    event_loop = asyncio.get_event_loop()

    if not (settings := ctx.find_object(conf.Settings)):
        raise RuntimeError("Configuration not found")

    client = asyva.Client()

    try:
        event_loop.run_until_complete(
            asyncio.gather(
                client.__aenter__(), async_apply(settings, client, filename, recursive)
            )
        )
    finally:
        event_loop.run_until_complete(client.__aexit__())


__all__ = ["apply"]
