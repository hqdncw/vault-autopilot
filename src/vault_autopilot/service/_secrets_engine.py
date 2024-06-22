from dataclasses import dataclass
from logging import getLogger
from typing import Any

from deepdiff import DeepDiff
from humps import camelize

from vault_autopilot._pkg.asyva.dto.secrets_engine import SecretsEngineConfig
from vault_autopilot._pkg.asyva.manager.kvv2 import ReadConfigurationResult
from vault_autopilot._pkg.asyva.manager.system_backend import (
    ReadMountConfigurationResult,
)

from .. import dto
from .._pkg import asyva
from ..service.abstract import ApplyResult
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


@dataclass(slots=True)
class SecretsEngineService:
    client: asyva.Client

    async def create(
        self,
        enable_options: asyva.dto.SecretsEngineEnableDTO,
        configure_options: asyva.dto.SecretsEngineConfigureDTO | None = None,
        tune_options: asyva.dto.SecretsEngineTuneMountConfigurationDTO | None = None,
    ) -> None:
        await self.client.enable_secrets_engine(**enable_options)
        await self.update(configure_options, tune_options)

    async def update(
        self,
        configure_options: asyva.dto.SecretsEngineConfigureDTO | None = None,
        tune_options: asyva.dto.SecretsEngineTuneMountConfigurationDTO | None = None,
    ) -> None:
        if configure_options:
            await self.client.configure_secrets_engine(**configure_options)
        if tune_options:
            await self.client.tune_mount_configuration(**tune_options)

    async def diff(
        self,
        payload: dto.SecretsEngineApplyDTO,
        mount_configuration: ReadMountConfigurationResult,
        kv_configuration: ReadConfigurationResult | None = None,
    ) -> dict[str, Any]:
        snapshot = dto.SecretsEngineApplyDTO(
            kind="SecretsEngine",
            spec=dto.SecretsEngineApplyDTO.Spec(
                path=payload.spec["path"],
                engine={  # type: ignore[reportArgumentType]
                    "type": payload.spec["engine"]["type"],
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
                **model_dump(
                    recursive_dict_filter(mount_configuration.data, config),
                    include=TUNE_FIELDS,
                )
            )

        return DeepDiff(
            snapshot,
            payload,
            ignore_order=True,
            verbose_level=2,
        )

    async def apply(self, payload: dto.SecretsEngineApplyDTO) -> ApplyResult:
        spec, engine = payload.spec, payload.spec["engine"]

        configure_options = (
            asyva.dto.SecretsEngineConfigureDTO(
                secret_mount_path=spec["path"],
                **options,
            )
            if (options := model_dump(engine, include=CONFIGURE_FIELDS))
            else None
        )
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

        result = await self.client.read_mount_configuration(path=spec["path"])

        if result is None:  # the secrets engine not found at given path
            try:
                await self.create(
                    dict(  # type: ignore[typeddict-item]
                        **model_dump(spec, exclude=("engine",)),
                        **model_dump(engine, exclude=CONFIGURE_FIELDS),
                    ),
                    configure_options,
                    tune_options,
                )
            except Exception as ex:
                return ApplyResult(status="create_error", error=ex)
            else:
                return ApplyResult(status="create_success")

        if diff := await self.diff(
            payload,
            mount_configuration=result,
            kv_configuration=(
                await self.client.read_kv_configuration(path=spec["path"])
                if configure_options is not None
                else None
            ),
        ):
            logger.debug(diff)

            try:
                # TODO: update modified fields only
                await self.update(configure_options, tune_options)
            except Exception as ex:
                return ApplyResult(status="update_error", error=ex)

            return ApplyResult(status="update_success")

        return ApplyResult(status="verify_success")
