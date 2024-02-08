import asyncio
import glob
import logging
import pathlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import IO, Iterator, NoReturn, Sequence, Union

import click
from rich.console import Group, RenderableType
from rich.text import Text

from ... import _conf, exc, parser
from ..._pkg import asyva
from ...dispatcher import Dispatcher, event
from ..exc import CLIError
from ..workflow import AbstractRenderer, AbstractStage, Workflow

__all__ = ["apply"]


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Record:
    content: str
    style: str = ""


class RecordStyle(StrEnum):
    INFO = "steel_blue3"
    CRITICAL = "yellow"


@dataclass(slots=True)
class RecordRenderer(AbstractRenderer):
    _records: dict[int, Record] = field(default_factory=dict)

    def create_or_update_record(
        self, record_uid: int, content: str, style: str = ""
    ) -> Record:
        record = Record(content=content, style=style)

        self._records.update({record_uid: record})

        return record

    def compose_renderable(self) -> RenderableType:
        return Group(
            *(
                self._compose_record_content(record)
                for record in self._records.values()
            ),
        )

    def _compose_record_content(self, record: Record) -> RenderableType:
        return Text(f"=> {record.content}", style=record.style)


@dataclass(slots=True)
class ApplyManifestsStage(AbstractStage):
    title: str = "Applying manifests"
    renderer: RecordRenderer = field(default_factory=RecordRenderer)


def raise_unexpected_exc(ex: Exception) -> NoReturn:
    logger.critical(ex, exc_info=ex)
    raise exc.ApplicationError("Unexpected error: %s" % ex)


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

    workflow = Workflow([ApplyManifestsStage()])
    stages = workflow.run()

    stage = await stages.__anext__()
    assert isinstance(stage, ApplyManifestsStage)

    TEMPLATE_DICT = {
        "apply_started": (
            "Applying {resource_kind} {absolute_path!r}...",
            RecordStyle.INFO,
        ),
        "verify_success": (
            "Verifying integrity of {resource_kind} {absolute_path!r}... done",
            RecordStyle.INFO,
        ),
        "verify_skipped": (
            "Verifying integrity of {resource_kind} {absolute_path!r}... SKIPPED (not "
            "implemented)",
            RecordStyle.INFO,
        ),
        "verify_error": (
            "Verifying integrity of {resource_kind} {absolute_path!r}... FAILED",
            RecordStyle.CRITICAL,
        ),
        "update_success": (
            "Updating {resource_kind} {absolute_path!r}... done",
            RecordStyle.INFO,
        ),
        "create_success": (
            "Creating {resource_kind} {absolute_path!r}... done",
            RecordStyle.INFO,
        ),
    }

    async def on_resource_update(
        ev: Union[event.ResourceApplyStarted, event.ResourceApplySuccess]
    ) -> None:
        if isinstance(ev, event.ResourceApplyStarted):  # type: ignore[arg-type]
            template = TEMPLATE_DICT["apply_started"]
        elif isinstance(ev, event.ResourceVerifySuccess):  # type: ignore[arg-type]
            if isinstance(ev, (event.IssuerVerifySuccess)):
                template = TEMPLATE_DICT["verify_skipped"]
            else:
                template = TEMPLATE_DICT["verify_success"]
        elif isinstance(ev, event.ResourceUpdateSuccess):  # type: ignore[arg-type]
            template = TEMPLATE_DICT["update_success"]
        elif isinstance(
            ev,
            Union[
                event.ResourceUpdateError,
                event.ResourceCreateError,
                event.ResourceVerifyError,
            ],  # type: ignore[arg-type]
        ):
            template = TEMPLATE_DICT["verify_error"]
        elif isinstance(ev, event.ResourceCreateSuccess):  # type: ignore[arg-type]
            template = TEMPLATE_DICT["create_success"]
        else:
            raise RuntimeError("Unexpected event type: %r" % ev)

        path = ev.resource.absolute_path()
        stage.renderer.create_or_update_record(
            record_uid=hash(path),
            content=template[0].format(
                resource_kind=ev.resource.kind,
                absolute_path=path,
            ),
            style=template[1],
        )

    async def configure_dispatcher() -> Dispatcher:
        # dispatcher requires authenticated Vault client
        await client.authenticate(
            base_url=settings.base_url,
            authn=settings.auth,
            namespace=settings.default_namespace,
        )

        dispatcher = Dispatcher(
            client=client,
            queue=queue,
        )
        dispatcher.register_handler(
            (
                event.PasswordApplyStarted,
                event.PasswordUpdateError,
                event.PasswordCreateError,
                event.PasswordVerifyError,
                event.PasswordCreateSuccess,
                event.PasswordUpdateSuccess,
                event.PasswordVerifySuccess,
                event.IssuerApplyStarted,
                event.IssuerCreateError,
                event.IssuerUpdateError,
                event.IssuerVerifyError,
                event.IssuerCreateSuccess,
                event.IssuerUpdateSuccess,
                event.IssuerVerifySuccess,
                event.PasswordPolicyApplyStarted,
                event.PasswordPolicyVerifyError,
                event.PasswordPolicyUpdateError,
                event.PasswordPolicyCreateError,
                event.PasswordPolicyCreateSuccess,
                event.PasswordPolicyUpdateSuccess,
                event.PasswordPolicyVerifySuccess,
                event.PKIRoleApplyStarted,
                event.PKIRoleUpdateError,
                event.PKIRoleCreateError,
                event.PKIRoleVerifyError,
                event.PKIRoleCreateSuccess,
                event.PKIRoleUpdateSuccess,
                event.PKIRoleVerifySuccess,
            ),
            callback=on_resource_update,
        )

        return dispatcher

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task((await configure_dispatcher()).dispatch())
            tg.create_task(
                parser.ManifestParser(
                    queue,
                    stream_data_from_files() if patterns else stream_data_from_stdin(),
                ).execute()
            )
    except ExceptionGroup as ex:
        workflow.stop(reason="failed")

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
                # TODO: Instead of just saying "Policy not found", provide the user with
                #  a more informative error message that includes the line number in the
                #  manifest file where the policy path was defined.
                asyva.exc.PasswordPolicyNotFoundError,
                exc.SecretVersionMismatchError,
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
        workflow.stop(reason="failed")
        raise_unexpected_exc(e)
    else:
        workflow.stop(reason="finished")

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
    Apply a manifest to a Vault server by file name, directory, or stdin.

    This command modifies Vault secrets using resources defined in a YAML manifest.
    The manifest specifies the desired state of the resources, and Autopilot ensures
    the actual state matches the desired state.

    Manifest Format:

    \b
      A Vault Autopilot manifest is a configuration file written in YAML that tells
      Autopilot what resources you want to create, update, or check on a Vault Server.
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

    logger.warning(
        "Verify integrity operation for Issuer, PKIRole, and PasswordPolicy not "
        "implemented"
    )

    try:
        event_loop.run_until_complete(
            async_apply(settings, client, filename, recursive)
        )
    finally:
        event_loop.run_until_complete(client.__aexit__())
        # Zero-sleep to allow underlying connections to close
        # https://docs.aiohttp.org/en/stable/client_advanced.html?highlight=sleep#graceful-shutdown
        event_loop.run_until_complete(asyncio.sleep(0))
