import asyncio
import glob
import pathlib
from dataclasses import dataclass, field
from enum import StrEnum
from logging import getLogger
from typing import IO, Any, Iterator, NoReturn, Sequence, Union

import click
from ironfence import Mutex
from pydantic import Field
from rich.console import Group, RenderableType
from rich.text import Text
from vault_autopilot import dto
from vault_autopilot._pkg.asyva.exc import SecretsEnginePathInUseError
from vault_autopilot.parser import AbstractManifestObject, ManifestParser
from vault_autopilot.processor.issuer import IssuerApplyProcessor
from vault_autopilot.processor.password import PasswordApplyProcessor
from vault_autopilot.processor.password_policy import PasswordPolicyApplyProcessor
from vault_autopilot.processor.pki_role import PKIRoleApplyProcessor
from vault_autopilot.processor.secrets_engine import SecretsEngineApplyProcessor
from vault_autopilot.processor.ssh_key import SSHKeyApplyProcessor
from vault_autopilot.repo.snapshot import SnapshotRepo
from vault_autopilot.util.dependency_chain import DependencyChain

from ... import _conf, exc
from ..._pkg import asyva
from ...dispatcher import Dispatcher, event
from ...service import (
    IssuerService,
    PasswordPolicyService,
    PasswordService,
    PKIRoleService,
    SecretsEngineService,
    SSHKeyService,
)
from ...service._issuer import IssuerSnapshot
from ...util.coro import BoundlessSemaphore
from ..exc import CLIError
from ..workflow import AbstractRenderer, AbstractStage, Workflow

__all__ = ["apply"]


logger = getLogger(__name__)


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


class ManifestObject(AbstractManifestObject):
    root: (
        dto.PKIRoleApplyDTO
        | dto.IssuerApplyDTO
        | dto.PasswordApplyDTO
        | dto.SecretsEngineApplyDTO
        | dto.PasswordPolicyApplyDTO
        | dto.SSHKeyApplyDTO
    ) = Field(discriminator="kind")


@dataclass(slots=True)
class ApplyManifestsStage(AbstractStage):
    title: str = "Applying manifests"
    renderer: RecordRenderer = field(default_factory=RecordRenderer)


def raise_unexpected_exc(ex: Exception) -> NoReturn:
    logger.debug(ex, exc_info=ex)
    raise CLIError("Unexpected error: %r" % ex, exit_code=128) from ex


async def async_apply(
    settings: _conf.Settings,
    client: asyva.Client,
    patterns: Sequence[str],
    recursive: bool,
) -> None:
    queue = asyncio.Queue[ManifestObject | None]()

    workflow = Workflow([ApplyManifestsStage()])
    stages = workflow.run()

    stage = await stages.__anext__()
    assert isinstance(stage, ApplyManifestsStage), stage

    issuer_repo = SnapshotRepo[IssuerSnapshot](
        {},
        IssuerSnapshot,
    )

    async def authenticate_client() -> asyva.Client:
        return await client.authenticate(
            base_url=settings.base_url,
            authn=settings.auth,
            namespace=settings.default_namespace,
        )

    async def initialize_database() -> None:
        try:
            await client.enable_secrets_engine(
                type="kv-v1",
                path=settings.storage["secrets_engine_path"],
                description=(
                    "Important: Do not modify or delete. This secrets engine is "
                    "automatically generated and managed by the Vault-Autopilot CLI. "
                    "Any unauthorized changes may result in resource desynchronization "
                    "and data loss."
                ),
            )
        except SecretsEnginePathInUseError:
            logger.debug(
                "the secrets engine %r is already created",
                settings.storage["secrets_engine_path"],
            )
        else:
            logger.debug(
                "the secrets engine %r has been created",
                settings.storage["secrets_engine_path"],
            )

        issuer_repo.storage = (
            raw_data.data
            if (
                raw_data := await client.read_kvv1_secret(
                    mount_path=settings.storage["secrets_engine_path"],
                    path=settings.storage["snapshots_secret_path"],
                )
            )
            else {}
        )

    async def flush_database() -> None:
        if client.is_authenticated and issuer_repo.storage:
            await client.update_or_create_kvv1_secret(
                mount_path=settings.storage["secrets_engine_path"],
                path=settings.storage["snapshots_secret_path"],
                data=issuer_repo.storage,
            )

    async def configure_dispatcher() -> (
        Dispatcher[ManifestObject | None, event.EventType]
    ):
        observer, sem = event.EventObserver[event.EventType](), BoundlessSemaphore()

        def proc_kwargs() -> dict[str, Any]:
            return {
                "sem": sem,
                "client": client,
                "observer": observer,
            }

        def event_builder(
            payload: ManifestObject | None,
        ) -> event.ResourceApplicationRequested | event.ShutdownRequested:
            if payload is None:
                return event.ShutdownRequested()

            root = payload.root
            match root.kind:
                case "Password":
                    assert isinstance(root, dto.PasswordApplyDTO)
                    return event.PasswordApplicationRequested(root)
                case "Issuer":
                    assert isinstance(root, dto.IssuerApplyDTO)
                    return event.IssuerApplicationRequested(root)
                case "PasswordPolicy":
                    assert isinstance(root, dto.PasswordPolicyApplyDTO)
                    return event.PasswordPolicyApplicationRequested(root)
                case "PKIRole":
                    assert isinstance(root, dto.PKIRoleApplyDTO)
                    return event.PKIRoleApplicationRequested(root)
                case "SecretsEngine":
                    assert isinstance(root, dto.SecretsEngineApplyDTO)
                    return event.SecretsEngineApplicationRequested(root)
                case "SSHKey":
                    assert isinstance(root, dto.SSHKeyApplyDTO)
                    return event.SSHKeyApplicationRequested(root)

                case _:
                    raise TypeError("Unexpected payload type: %r" % payload)

        dispatcher = Dispatcher[ManifestObject | None, event.EventType](
            client=client,
            observer=observer,
            event_builder=event_builder,
            processing_registry={
                "Password": PasswordApplyProcessor(
                    pwd_svc=PasswordService(client),
                    # TODO: Allow processors to share the same dependency chain to
                    #  reduce memory consumption.
                    dep_chain=Mutex(DependencyChain()),
                    **proc_kwargs(),
                ),
                "Issuer": IssuerApplyProcessor(
                    iss_svc=IssuerService(client, issuer_repo),
                    dep_chain=Mutex(DependencyChain()),
                    **proc_kwargs(),
                ),
                "PasswordPolicy": PasswordPolicyApplyProcessor(
                    pwd_policy_svc=PasswordPolicyService(client), **proc_kwargs()
                ),
                "PKIRole": PKIRoleApplyProcessor(
                    pki_role_svc=PKIRoleService(client),
                    dep_chain=Mutex(DependencyChain()),
                    **proc_kwargs(),
                ),
                "SecretsEngine": SecretsEngineApplyProcessor(
                    secrets_engine_svc=SecretsEngineService(client), **proc_kwargs()
                ),
                "SSHKey": SSHKeyApplyProcessor(
                    ssh_key_svc=SSHKeyService(client),
                    dep_chain=Mutex(DependencyChain()),
                    **proc_kwargs(),
                ),
            },
            queue=queue,
        )

        TEMPLATE_DICT = {
            "application_requested": (
                "Applying {resource_kind} {absolute_path!r}...",
                RecordStyle.INFO,
            ),
            "verify_success": (
                "Verifying integrity of {resource_kind} {absolute_path!r}... done",
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
            "update_error": (
                "Updating {resource_kind} {absolute_path!r}... FAILED",
                RecordStyle.CRITICAL,
            ),
            "create_success": (
                "Creating {resource_kind} {absolute_path!r}... done",
                RecordStyle.INFO,
            ),
            "create_error": (
                "Creating {resource_kind} {absolute_path!r}... FAILED",
                RecordStyle.CRITICAL,
            ),
        }

        async def on_resource_update(
            ev: Union[
                event.ResourceApplicationRequested,
                event.ResourceApplicationInitiated,
                event.ResourceApplySuccess,
                event.ResourceApplyError,
            ],
        ) -> None:
            if isinstance(ev, event.ResourceApplicationRequested):
                template = TEMPLATE_DICT["application_requested"]
            elif isinstance(ev, event.ResourceApplicationInitiated):
                return
            elif isinstance(ev, event.ResourceVerifySuccess):
                template = TEMPLATE_DICT["verify_success"]
            elif isinstance(ev, event.ResourceVerifyError):
                template = TEMPLATE_DICT["verify_error"]
            elif isinstance(ev, event.ResourceUpdateSuccess):
                template = TEMPLATE_DICT["update_success"]
            elif isinstance(ev, event.ResourceUpdateError):
                template = TEMPLATE_DICT["update_error"]
            elif isinstance(ev, event.ResourceCreateSuccess):
                template = TEMPLATE_DICT["create_success"]
            elif isinstance(ev, event.ResourceCreateError):
                template = TEMPLATE_DICT["create_error"]
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

        dispatcher.register_handler(
            (
                event.PasswordApplicationRequested,
                event.PasswordApplicationInitiated,
                event.PasswordUpdateError,
                event.PasswordCreateError,
                event.PasswordVerifyError,
                event.PasswordCreateSuccess,
                event.PasswordUpdateSuccess,
                event.PasswordVerifySuccess,
                event.IssuerApplicationRequested,
                event.IssuerApplicationInitiated,
                event.IssuerCreateError,
                event.IssuerUpdateError,
                event.IssuerVerifyError,
                event.IssuerCreateSuccess,
                event.IssuerUpdateSuccess,
                event.IssuerVerifySuccess,
                event.PasswordPolicyApplicationRequested,
                event.PasswordPolicyApplicationInitiated,
                event.PasswordPolicyVerifyError,
                event.PasswordPolicyUpdateError,
                event.PasswordPolicyCreateError,
                event.PasswordPolicyCreateSuccess,
                event.PasswordPolicyUpdateSuccess,
                event.PasswordPolicyVerifySuccess,
                event.PKIRoleApplicationRequested,
                event.PKIRoleApplicationInitiated,
                event.PKIRoleUpdateError,
                event.PKIRoleCreateError,
                event.PKIRoleVerifyError,
                event.PKIRoleCreateSuccess,
                event.PKIRoleUpdateSuccess,
                event.PKIRoleVerifySuccess,
                event.SecretsEngineApplicationRequested,
                event.SecretsEngineApplicationInitiated,
                event.SecretsEngineUpdateError,
                event.SecretsEngineCreateError,
                event.SecretsEngineVerifyError,
                event.SecretsEngineCreateSuccess,
                event.SecretsEngineUpdateSuccess,
                event.SecretsEngineVerifySuccess,
                event.SSHKeyApplicationRequested,
                event.SSHKeyApplicationInitiated,
                event.SSHKeyCreateError,
                event.SSHKeyUpdateError,
                event.SSHKeyVerifyError,
                event.SSHKeyCreateSuccess,
                event.SSHKeyUpdateSuccess,
                event.SSHKeyVerifySuccess,
            ),
            callback=on_resource_update,
        )

        return dispatcher

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

    async def handle_manifests():
        await authenticate_client()
        await initialize_database()
        await (await configure_dispatcher()).dispatch()

    err = None

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(handle_manifests())
            tg.create_task(
                ManifestParser(
                    stream_data_from_files() if patterns else stream_data_from_stdin(),
                    ManifestObject,
                    queue,
                ).execute()
            )
    except Exception as ex:
        err = ex

    try:
        await flush_database()
    except Exception as ex:
        if err is None:
            err = ex

    if err is not None:
        workflow.stop("failed")

        click.echo("\nOops! Something went wrong while applying the manifests.\n")

        while True:
            if isinstance(err, ExceptionGroup):
                err = err.exceptions[0]
                continue
            break

        if isinstance(err, asyva.exc.UnauthorizedError):
            raise CLIError("Authorization failed: %s" % err) from err

        if isinstance(err, (exc.ManifestError, ConnectionRefusedError)):
            raise CLIError(str(err)) from err

        if isinstance(
            err,
            (
                # TODO: Instead of just saying "Policy not found", provide the user with
                #  a more informative error message that includes the line number in the
                #  manifest file where the policy path was defined.
                asyva.exc.PasswordPolicyNotFoundError,
                asyva.exc.SecretsEnginePathInUseError,
                exc.ResourceIntegrityError,
            ),
        ):
            # TODO: print the contents of a YAML file, highlighting any invalid
            #  lines.
            raise CLIError(str(err), exit_code=128) from err

        if isinstance(err, CLIError):
            raise err

        raise_unexpected_exc(err)

    workflow.stop("finished")
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
    Apply a manifest to a Vault server from a file, directory, or standard input.

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
