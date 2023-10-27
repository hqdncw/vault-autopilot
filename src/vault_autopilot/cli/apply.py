import asyncio
import itertools
import logging
import pathlib
from typing import IO, Iterator, NoReturn

import click

from .. import conf, dispatcher, exc, pipeline, service
from .._pkg import asyva

logger = logging.getLogger(__name__)

FilenamesOption = list[pathlib.Path]


MANIFEST_PATTERNS = (".yml", ".yaml")


def read_files(
    filenames: Iterator[pathlib.Path], pass_stdin: bool = False
) -> Iterator[IO[bytes]]:
    """
    If `pass_stdin` is True, ignores the provided file paths and reads the contents of
    STDIN instead. Otherwise, opens each file path in binary mode using `open()` and
    yields its contents as an iterator.

    Args:
        filenames: An iterator of regular files to read from.
        pass_stdin: Whether to read from STDIN instead of the `filenames`

    Yields:
        I/O objects representing the contents of the given files.
    """
    if pass_stdin:
        logger.debug("streaming manifests from stdin")
        yield click.get_binary_stream(name="stdin")
    else:
        for fn in filenames:
            logger.debug("streaming file %r" % fn)
            yield open(fn, "rb")


def get_matching_files(
    path: pathlib.Path, suffix: str, recursive: bool = False
) -> Iterator[pathlib.Path]:
    """
    Searches for regular files with the specified suffix within the given directory,
    optionally searching recursively through subdirectories.

    Args:
        path:
            The directory to search for regular files. If a regular
            file is provided, it will be yielded if it matches the suffix.
        suffix:
            The suffix to search for. The suffix should include a dot (.)
            followed by the desired extension. For example, ".txt" or ".pdf".
        recursive:
            Whether to search recursively through subdirectories.

    Yields:
        Each regular file that matches the specified suffix.

    Examples:
        >>> list(get_matching_files("example/a.txt", ".txt")) == ["example/a.txt"]
        True
        >>> list(get_matching_files("example", ".txt")) ==\\
        ... ["example/a.txt", "example/b.txt"]
        True
        >>> list(get_matching_files("example", "doesnotexist")) == []
        True
        >>> list(get_matching_files("example", ".txt", recursive=True)) ==\\
        ... ["example/a.txt", "example/b.txt", "example/subdirectory/c.txt"]
        True
    """
    assert suffix.startswith(
        "."
    ), "Suffix must start with a dot (.) followed by the desired extension"
    for path in filter(
        lambda path: path.is_file() and path.suffix == suffix and path.stat(),
        (
            (path,)
            if path.is_file()
            else path.rglob("*")
            if recursive
            else path.iterdir()
        ),
    ):
        yield path


def gather_manifests(
    filenames: FilenamesOption,
    recursive: bool,
    patterns: tuple[str, ...] = MANIFEST_PATTERNS,
) -> Iterator[pathlib.Path]:
    """
    Gathers all regular files found in the given file paths, recursively searching
    through subdirectories if `recursive` is set to `True`. If a regular file is
    provided instead of a directory, it will be yielded without validating its
    extension. This allows for cases where a file with an unknown extension needs to
    be processed as a manifest.

    Args:
        filenames: A list of file paths.
        recursive: A boolean indicating whether to search through subdirectories.

    Yields:
        Manifest file path.
    """
    for path in filenames:
        logger.debug("resolving %r" % path)

        for fn in itertools.chain(
            *(
                get_matching_files(path, suffix=suffix, recursive=recursive)
                for suffix in patterns
            ),
            ((path,) if path.is_file() and path.suffix not in patterns else ()),
        ):
            logger.debug("discovered file %r" % fn)
            yield fn


def stdin_has_data(filenames: FilenamesOption) -> bool:
    """Returns `True` if user requested the program to read from stdin, `False`
    otherwise."""
    return any(val.name == "-" for val in filenames) if filenames else False


def raise_unexpected_err(ex: Exception) -> NoReturn:
    logger.critical(ex, exc_info=ex)
    raise exc.ApplicationError("Unexpected error: %s" % ex) from ex


async def async_apply(
    settings: conf.Settings,
    client: asyva.Client,
    filenames: FilenamesOption,
    recursive: bool,
) -> None:
    if (stdin_nonempty := stdin_has_data(filenames=filenames)) and len(filenames) > 1:
        raise exc.StdinInputCombinationError("Cannot combine stdin with filenames (-f)")

    queue: pipeline.QueueType = asyncio.PriorityQueue()

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                client.authenticate(
                    base_url=settings.base_url,
                    authn=settings.auth.get_authenticator(),
                    namespace=settings.default_namespace,
                )
            )
            tg.create_task(
                pipeline.YamlPipeline(
                    queue=queue,
                    streamer=read_files(
                        filenames=gather_manifests(
                            filenames, recursive, MANIFEST_PATTERNS
                        ),
                        pass_stdin=stdin_nonempty,
                    ),
                ).execute()
            )
    except ExceptionGroup as eg:
        ex = eg.exceptions[0]

        if isinstance(
            ex, (asyva.exc.ConnectionRefusedError, asyva.exc.UnauthorizedError)
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

    # TODO: make the pipeline implementation coroutine-safe, so that we can run the
    # dispatcher concurrently.
    try:
        await dispatcher.Dispatcher(
            passwd_svc=service.PasswordService(client=client),
            passwd_policy_svc=service.PasswordPolicyService(client=client),
            issuer_svc=service.IssuerService(client=client),
            queue=queue,
        ).dispatch()
    except ExceptionGroup as eg:
        ex = eg.exceptions[0]

        if isinstance(
            ex,
            (
                asyva.exc.CASParameterMismatchError,
                asyva.exc.PasswordPolicyNotFoundError,
                asyva.exc.IssuerNameTakenError,
            ),
        ):
            # TODO: print the contents of a YAML file, highlighting any invalid
            #  lines.
            raise exc.ApplicationError(str(ex))
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
    type=click.Path(  # type: ignore[type-var]
        readable=True,
        path_type=pathlib.Path,  # pyright: ignore[reportGeneralTypeIssues]
    ),
    multiple=True,
    required=True,
    help="The manifest to apply (can be repeated)",
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
            async_apply(settings, client, filename, recursive)
        )
    finally:
        event_loop.run_until_complete(client.__aexit__())


__all__ = ["apply"]
