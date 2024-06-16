import logging
from http import HTTPStatus
from typing import Any

from typing_extensions import TypedDict, Unpack

from vault_autopilot.util.model import model_dump

from .. import constants, dto
from ..exc import (
    CASParameterMismatchError,
    InvalidPathError,
    VaultAPIError,
)
from .base import AbstractResult, BaseManager

logger = logging.getLogger(__name__)


class UpdateOrCreateResult(AbstractResult):
    class Data(TypedDict):
        created_time: str
        custom_metadata: dict[str, Any]
        deletion_time: str
        destroyed: bool
        version: int

    data: Data


class ReadConfigurationResult(AbstractResult):
    class Data(TypedDict):
        cas_required: bool
        delete_version_after: str
        max_versions: int

    data: Data


class ReadMetadataResult(AbstractResult):
    class VersionInfo(TypedDict):
        created_time: str
        deletion_time: str
        destroyed: bool

    class Data(ReadConfigurationResult.Data):
        created_time: str
        current_version: int
        oldest_version: int
        updated_time: str
        custom_metadata: dict[str, str] | None
        versions: dict[str, "ReadMetadataResult.VersionInfo"]

    data: Data


class KVV2Manager(BaseManager):
    async def update_or_create(
        self, **payload: Unpack[dto.SecretCreateDTO]
    ) -> UpdateOrCreateResult:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-secret
        """
        data, mount_path, path = (
            {"data": payload["data"]},
            payload["mount_path"],
            payload["path"],
        )

        if isinstance((cas := payload.get("cas")), int):
            data.update({"options": {"cas": cas}})

        async with self.new_session() as sess:
            resp = await sess.post("/v1/%s/data/%s" % (mount_path, path), json=data)

        result = await resp.json()

        if resp.status == HTTPStatus.OK:
            return UpdateOrCreateResult.from_response(result)

        for msg in result.get("errors", {}):
            if constants.CAS_MISMATCH in msg:
                ctx = CASParameterMismatchError.Context(
                    **await VaultAPIError.compose_context(resp),
                    secret="/".join((mount_path, path)),
                )

                if cas is not None:
                    ctx.update({"provided_cas": cas})

                try:
                    ctx.update(
                        {
                            "required_cas": (
                                await self.read_metadata(
                                    mount_path=mount_path, path=path
                                )
                            ).data["current_version"]
                        }
                    )
                except InvalidPathError:
                    ctx.update({"required_cas": 0})
                except VaultAPIError as ex:
                    logger.debug("Failed to fetch the required cas value", exc_info=ex)

                raise CASParameterMismatchError(
                    message=(
                        "Failed to push secret {ctx[secret]!r}: CAS mismatch "
                        "(expected {ctx[required_cas]!r}, got {ctx[provided_cas]!r}). "
                        "Ensure correct CAS value and try again"
                    ),
                    ctx=ctx,
                )

        raise await VaultAPIError.from_response("Failed to create/update secret", resp)

    async def update_or_create_metadata(
        self, **payload: Unpack[dto.SecretUpdateOrCreateMetadata]
    ) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/metadata/%s" % (payload["mount_path"], payload["path"]),
                json=model_dump(payload, exclude=("mount_path", "path")),
            )

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response(
            "Failed to update/create secret metadata", resp
        )

    async def read_metadata(
        self, **payload: Unpack[dto.SecretReadDTO]
    ) -> ReadMetadataResult:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/v1/%s/metadata/%s" % (payload["mount_path"], payload["path"])
            )

        if resp.status == HTTPStatus.OK:
            return ReadMetadataResult.from_response(await resp.json() or {})

        raise await VaultAPIError.from_response("Failed to read secret metadata", resp)

    async def configure_secret_engine(
        self, **payload: Unpack[dto.SecretsEngineConfigureDTO]
    ) -> None:
        """
        References:
            <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#configure-the-kv-engine>
        """
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/config" % payload["secret_mount_path"], json=payload
            )

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response(
            "Failed to configure secrets engine", resp
        )

    async def read_configuration(
        self, **payload: Unpack[dto.SecretsEngineReadDTO]
    ) -> ReadConfigurationResult:
        """
        References:
            <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-kv-engine-configuration>
        """
        async with self.new_session() as sess:
            resp = await sess.get("/v1/%s/config" % payload["path"])

        if resp.status == HTTPStatus.OK:
            return ReadConfigurationResult.from_response(await resp.json())

        raise await VaultAPIError.from_response(
            "Failed to read kv engine configuration", resp
        )
