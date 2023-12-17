import asyncio
import glob
import logging
import pathlib
from typing import IO, Iterator, NoReturn, Sequence

import click

from .. import _conf, dispatcher, exc, parser
from .._pkg import asyva
from .exc import CLIError

__all__ = ["apply"]


logger = logging.getLogger(__name__)


def raise_unexpected_exc(ex: Exception) -> NoReturn:
    logger.critical(ex, exc_info=ex)
    raise exc.ApplicationError("Unexpected error: %s" % ex) from ex


async def async_apply(
    settings: _conf.Settings,
    client: asyva.Client,
    patterns: Sequence[str],
    recursive: bool,
) -> None:
    queue: parser.QueueType = asyncio.Queue()

    def stream_data_from_files() -> Iterator[IO[bytes]]:
        """Yields an iterator of binary file objects for regular files matching given
        patterns (simple filenames or globs). Skips dirs if recursive is False;
        otherwise, includes all matching files in the dir."""
        for pat in patterns:
            counter = 0

            for fn in glob.iglob(pat, recursive=recursive):
                if pathlib.Path(fn).is_dir():
                    continue

                logger.debug("streaming manifest %r", fn)
                yield open(fn, "rb")

                counter += 1

            if counter == 0:
                raise CLIError(
                    "No files were found that match the pattern %r. Make sure the "
                    "pattern matches at least one existing regular file, or use the -R "
                    "option to search recursively." % pat
                )

            logger.debug("found %d manifest(s) matching pattern %r", counter, pat)

    def stream_data_from_stdin() -> Iterator[IO[bytes]]:
        """Yields an iterator of binary data from standard input."""
        yield click.get_binary_stream("stdin")

    async def start_dispatcher() -> None:
        """
        Ensures the client is authenticated before dispatching tasks.

        The Dispatcher class requires an authenticated client, so we prioritize
        authentication before calling .dispatch(). This ensures a seamless
        transition between authentication and task execution.
        """
        await client.authenticate(
            base_url=settings.base_url,
            authn=settings.auth,
            namespace=settings.default_namespace,
        )
        await dispatcher.Dispatcher(
            client=client,
            queue=queue,
        ).dispatch()

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(start_dispatcher())
            tg.create_task(
                parser.ManifestParser(
                    queue,
                    stream_data_from_files() if patterns else stream_data_from_stdin(),
                ).execute()
            )
    except ExceptionGroup as ex:
        while True:
            if isinstance(ex, ExceptionGroup):
                ex = ex.exceptions[0]
                continue
            break

        if isinstance(
            ex, (asyva.exc.ConnectionRefusedError, asyva.exc.UnauthorizedError)
        ):
            logger.debug(ex, exc_info=ex)
            raise CLIError("Authentication error: %s" % ex) from ex
        elif isinstance(ex, exc.ManifestError):
            raise CLIError("Invalid manifest file: %s" % ex) from ex
        elif isinstance(
            ex,
            (
                asyva.exc.CASParameterMismatchError,
                # TODO: Instead of just saying "Policy not found", provide the user with
                #  a more informative error message that includes the line number in the
                #  manifest file where the policy path was defined.
                asyva.exc.PasswordPolicyNotFoundError,
                asyva.exc.IssuerNameTakenError,
            ),
        ):
            # TODO: print the contents of a YAML file, highlighting any invalid
            #  lines.
            raise CLIError(str(ex)) from ex
        elif isinstance(ex, CLIError):
            raise ex
        else:
            raise_unexpected_exc(ex)
    except Exception as e:
        raise_unexpected_exc(e)

    click.secho("Thanks for choosing Vault Autopilot!", fg="yellow")


# TODO: epilog https://click.palletsprojects.com/en/8.1.x/documentation/#command-epilog-help
# TODO: ca-cert, ca-path, client-cert, client-key
@click.command()
@click.option(
    "-f",
    "--filename",
    type=click.Path(path_type=str),
    multiple=True,
    help=(
        "Specify the path to the manifest file(s) you want to apply (can be repeated). "
        "Accepts Unix globbing patterns, which allow you to specify multiple files or "
        "directories at once. If you omit this option, the command will read the "
        "manifests from standard input."
    ),
)
@click.option(
    "-R",
    "--recursive",
    is_flag=True,
    default=False,
    help=(
        "Process the directories used in `-f`, `--filename` recursively. Useful when "
        "you want to manage related manifests organized within the same directory."
    ),
)
@click.pass_context
def apply(
    ctx: click.Context,
    filename: Sequence[str],
    recursive: bool,
) -> None:
    """
    Apply a manifest to a Vault server by file name or stdin.

    Manifest Format:

    \b
      A Vault Autopilot manifest is a configuration file written in YAML that tells
      Autopilot what resources you want to create, update, or delete on a Vault Server.
    \b
      Each resource in the manifest has three important fields: apiVersion, kind, and
      spec. The apiVersion field specifies the API version of the resource, the kind
      field identifies the type of resource, and the spec field contains the
      specifications for the resource. Think of a manifest as a blueprint for your Vault
      Server - it defines the desired state of your resources, and Autopilot works to
      ensure that the actual state matches the desired state defined in the manifest.

    Examples:

    \b
      # Apply a manifest from a file
      $ vault-autopilot apply -f manifest.yaml
    \b
      # Apply manifests from a folder recursively
      $ vault-autopilot apply -Rf /path/to/folder/**/*.yaml
    \b
      # Apply a manifest from standard input
      $ cat manifest.yaml | vault-autopilot apply
    """
    event_loop = asyncio.get_event_loop()

    if not (settings := ctx.find_object(_conf.Settings)):
        raise RuntimeError("Configuration not found")

    client = asyva.Client()

    try:
        event_loop.run_until_complete(
            async_apply(settings, client, filename, recursive)
        )
    finally:
        event_loop.run_until_complete(client.__aexit__())
        # Zero-sleep to allow underlying connections to close
        # https://docs.aiohttp.org/en/stable/client_advanced.html?highlight=sleep#graceful-shutdown
        event_loop.run_until_complete(asyncio.sleep(0))
