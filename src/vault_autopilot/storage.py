from collections import UserDict
from dataclasses import dataclass, field
from logging import getLogger
from typing import Any

from ._pkg.asyva import Client as AsyvaClient
from ._pkg.asyva.exc import SecretsEnginePathInUseError

logger = getLogger(__name__)


DESCRIPTION = (
    "Important: Do not modify or delete. This secrets engine is "
    "automatically generated and managed by the Vault-Autopilot CLI. "
    "Any unauthorized changes may result in resource desynchronization "
    "and data loss."
)


@dataclass(slots=True)
class KvV2SecretStorage(UserDict):
    secrets_engine_path: str
    snapshots_secret_path: str
    client: AsyvaClient
    data: dict[Any, Any] = field(init=False, default_factory=dict)

    async def initialize(self) -> None:
        try:
            await self.client.enable_secrets_engine(
                type="kv-v1",
                path=self.secrets_engine_path,
                description=DESCRIPTION,
            )
        except SecretsEnginePathInUseError:
            logger.debug(
                "the secrets engine %r is already created", self.secrets_engine_path
            )

            result = await self.client.read_mount_configuration(
                path=self.secrets_engine_path
            )

            if result is None:
                raise RuntimeError("Unexpected behavior")

            if result.data.get("options", {}).get("version", None) != "1":
                raise RuntimeError(
                    f"Expected {self.secrets_engine_path!r} to point to a 'kv-v1' "
                    "secrets engine, but it doesn't"
                )
        else:
            logger.debug(
                "the secrets engine %r has been created", self.secrets_engine_path
            )

    async def pull(self) -> None:
        self.data = (
            result.data
            if (
                result := await self.client.read_kvv1_secret(
                    mount_path=self.secrets_engine_path,
                    path=self.snapshots_secret_path,
                )
            )
            else {}
        )

    async def push(self) -> None:
        if self.data:
            await self.client.update_or_create_kvv1_secret(
                mount_path=self.secrets_engine_path,
                path=self.snapshots_secret_path,
                data=self.data,
            )
