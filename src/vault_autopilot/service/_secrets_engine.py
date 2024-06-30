from dataclasses import dataclass
from functools import cached_property
from logging import getLogger
from typing import Any, Callable, ClassVar, Coroutine

from deepdiff import DeepDiff
from humps import camelize
from typing_extensions import Unpack

from vault_autopilot._pkg.asyva.dto.secrets_engine import (
    SecretsEngineConfig,
    SecretsEngineReadDTO,
)
from vault_autopilot._pkg.asyva.manager.system_backend import (
    ReadMountConfigurationResult,
)
from vault_autopilot.exc import ResourceIntegrityError
from vault_autopilot.repo.snapshot import SnapshotRepo

from .. import dto
from .._pkg import asyva
from ..service.abstract import ResourceApplyMixin
from ..util.model import model_dump, recursive_dict_filter

logger = getLogger(__name__)

CONFIGURE_FIELDS = (
    "cas_required",
    "delete_version_after",
    "max_versions",
)
TUNE_FIELDS = (
    "default_lease_ttl",
    "max_lease_ttl",
    "audit_non_hmac_request_keys",
    "audit_non_hmac_response_keys",
    "listing_visibility",
    "passthrough_request_headers",
    "allowed_response_headers",
    "allowed_managed_keys",
    "plugin_version",
    "delegated_auth_accessors",
)
ENABLE_FIELDS = (
    "description",
    "local",
    "seal_wrap",
    "external_entropy_access",
    "options",
)


SecretsEngineSnapshot = dto.SecretsEngineApplyDTO


def get_configure_options(
    payload: dto.SecretsEngineApplyDTO,
) -> asyva.dto.SecretsEngineConfigureDTO | None:
    return (
        asyva.dto.SecretsEngineConfigureDTO(
            secret_mount_path=payload.spec["path"],
            **options,
        )
        if (options := model_dump(payload.spec["engine"], include=CONFIGURE_FIELDS))
        else None
    )


@dataclass(slots=True)
class SecretsEngineService(
    ResourceApplyMixin[dto.SecretsEngineApplyDTO, SecretsEngineSnapshot]
):
    client: asyva.Client
    repo: SnapshotRepo[SecretsEngineSnapshot]
    immutable_fields: ClassVar[tuple[str, ...]] = (
        "root[[]'spec'[]][[]'engine'[]][[]'type'[]]",
        "root[[]'spec'[]][[]'engine'[]][[]'local'[]]",
        "root[[]'spec'[]][[]'engine'[]][[]'sealWrap'[]]",
        "root[[]'spec'[]][[]'engine'[]][[]'externalEntropyAccess'[]]",
    )

    async def create(
        self,
        enable_options: asyva.dto.SecretsEngineEnableDTO,
        configure_options: asyva.dto.SecretsEngineConfigureDTO | None = None,
        tune_options: asyva.dto.SecretsEngineTuneMountConfigurationDTO | None = None,
    ) -> None:
        await self.client.enable_secrets_engine(**enable_options)
        await self.update(configure_options, tune_options)

        await self.repo.put(
            enable_options["path"],
            SecretsEngineSnapshot.model_construct(
                spec=SecretsEngineSnapshot.Spec(engine={"type": enable_options["type"]})  # type: ignore[reportCallIssue]
            ),
        )

    async def update(
        self,
        configure_options: asyva.dto.SecretsEngineConfigureDTO | None = None,
        tune_options: asyva.dto.SecretsEngineTuneMountConfigurationDTO | None = None,
    ) -> None:
        if configure_options:
            await self.client.configure_secrets_engine(**configure_options)
        if tune_options:
            await self.client.tune_mount_configuration(**tune_options)

    async def get(
        self, **payload: Unpack[SecretsEngineReadDTO]
    ) -> ReadMountConfigurationResult | None:
        return await self.client.read_mount_configuration(**payload)

    @cached_property
    def update_or_create_executor(
        self,
    ) -> Callable[[dto.SecretsEngineApplyDTO], Coroutine[Any, Any, Any]]:
        async def wrapper(payload: dto.SecretsEngineApplyDTO):
            spec, engine = payload.spec, payload.spec["engine"]

            configure_options = get_configure_options(payload)
            tune_options = (
                asyva.dto.SecretsEngineTuneMountConfigurationDTO(
                    path=spec["path"], **options
                )
                if (
                    options := {
                        **model_dump(engine, include=("description",)),
                        **model_dump(engine.get("config", {}), include=TUNE_FIELDS),
                    }
                )
                else None
            )

            return (
                await self.create(
                    dict(  # type: ignore[typeddict-item]
                        **model_dump(spec, exclude=("engine",)),
                        **model_dump(engine, exclude=CONFIGURE_FIELDS),
                    ),
                    configure_options,
                    tune_options,
                )
                if await self.get(path=payload.spec["path"]) is None
                else await self.update(configure_options, tune_options)
            )

        return lambda payload: wrapper(payload)

    async def build_snapshot(
        self, payload: dto.SecretsEngineApplyDTO
    ) -> SecretsEngineSnapshot | None:
        configure_options = get_configure_options(payload)
        snapshot = await self.repo.get(payload.absolute_path())
        mount_configuration = await self.get(path=payload.spec["path"])
        kv_configuration = (
            await self.client.read_kv_configuration(path=payload.spec["path"])
            if configure_options is not None
            else None
        )

        snapshot_is_missing = snapshot is None
        resource_is_missing = mount_configuration is None

        if snapshot_is_missing and resource_is_missing:
            return None

        if snapshot_is_missing:
            raise ResourceIntegrityError(
                "Snapshot not found, resource integrity compromised",
                ResourceIntegrityError.Context(resource=payload),
            )

        if resource_is_missing:
            raise ResourceIntegrityError(
                "Failed to retrieve a snapshot, the required resource is missing",
                ResourceIntegrityError.Context(resource=payload),
            )

        snapshot = SecretsEngineSnapshot.model_construct(
            kind="SecretsEngine",
            spec=dto.SecretsEngineApplyDTO.Spec(
                path=payload.spec["path"],
                engine={  # type: ignore[reportArgumentType]
                    "type": snapshot.spec["engine"]["type"],
                    **camelize(
                        {
                            **(
                                model_dump(
                                    recursive_dict_filter(
                                        mount_configuration.data,
                                        payload.spec["engine"],
                                    ),
                                    include=ENABLE_FIELDS,
                                )
                                or {}
                            ),
                            **(
                                model_dump(
                                    recursive_dict_filter(
                                        kv_configuration.data,
                                        payload.spec["engine"],
                                    ),
                                )
                                if kv_configuration is not None
                                else {}
                            ),
                        }
                    ),
                },
            ),
        )

        if (config := payload.spec["engine"].get("config")) is not None:
            snapshot.spec["engine"]["config"] = SecretsEngineConfig(
                **camelize(
                    model_dump(
                        recursive_dict_filter(mount_configuration.data, config),
                        include=TUNE_FIELDS,
                    )
                )
            )

        return snapshot

    def diff(
        self, payload: dto.SecretsEngineApplyDTO, snapshot: SecretsEngineSnapshot
    ) -> dict[str, Any]:
        return DeepDiff(
            snapshot.__dict__,
            camelize(payload.__dict__),
            ignore_order=True,
            verbose_level=2,
        )
