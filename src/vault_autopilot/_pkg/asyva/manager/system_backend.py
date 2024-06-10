from http import HTTPStatus
from os import path
from typing import NotRequired

from vault_autopilot._pkg.asyva import constants
from vault_autopilot._pkg.asyva.exc import (
    SecretsEnginePathInUseError,
    VaultAPIError,
)
from vault_autopilot.util.model import model_dump

from .. import dto
from ..dto.secrets_engine import KvV2Options, SecretsEngineConfig
from .base import AbstractResult, BaseManager

BASE_PATH = "/v1/sys/mounts/"


class ReadMountConfigurationResult(AbstractResult):
    class Data(SecretsEngineConfig):
        description: str
        options: NotRequired[KvV2Options]
        external_entropy_access: NotRequired[bool]

    data: Data


class SystemBackendManager(BaseManager):
    async def enable_secrets_engine(self, payload: dto.SecretsEngineEnableDTO) -> None:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/system/mounts#enable-secrets-engine
        """

        async with self.new_session() as sess:
            resp = await sess.post(
                path.join(BASE_PATH, payload["path"]),
                json=model_dump(payload, exclude=("path",)),
            )

        result = await resp.json() or {}

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        for msg in result.get("errors", {}):
            if constants.PATH_IN_USE in msg:
                if not resp.status == HTTPStatus.BAD_REQUEST:
                    continue

                raise SecretsEnginePathInUseError(
                    "The path {ctx[path_collision]!r} for the secrets engine is "
                    "already in use. Please choose a different path or disable the "
                    "existing engine at this path",
                    ctx=SecretsEnginePathInUseError.Context(
                        **await VaultAPIError.compose_context(resp),
                        path_collision=payload["path"],
                        mount_path="sys/mounts",
                    ),
                )

        raise await VaultAPIError.from_response("Failed to enable secrets engine", resp)

    async def tune_mount_configuration(
        self, payload: dto.SecretsEngineTuneMountConfigurationDTO
    ) -> None:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/system/mounts#tune-mount-configuration
        """
        async with self.new_session() as sess:
            resp = await sess.post(
                path.join(BASE_PATH, payload["path"], "tune"),
                json=model_dump(payload, exclude=("path",)),
            )

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response(
            "Failed to tune mount configuration", resp
        )

    async def read_mount_configuration(
        self, payload: dto.SecretsEngineGetDTO
    ) -> ReadMountConfigurationResult | None:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/system/mounts#read-mount-configuration
        """
        async with self.new_session() as sess:
            resp = await sess.get(
                path.join(BASE_PATH, payload["path"], "tune"),
                json=model_dump(payload, exclude=("path",)),
            )

        if resp.status == HTTPStatus.OK:
            return ReadMountConfigurationResult.from_response(await resp.json() or {})

        result = await resp.json() or {}

        for msg in result.get("errors", {}):
            if constants.SYSVIEW_FETCH_ERROR in msg:
                if not resp.status == HTTPStatus.BAD_REQUEST:
                    continue

                return None

        raise await VaultAPIError.from_response(
            "Failed to read mount configuration", resp
        )
