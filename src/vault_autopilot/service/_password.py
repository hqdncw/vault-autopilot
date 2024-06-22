from dataclasses import dataclass

from humps import camelize
from typing_extensions import override

from vault_autopilot.util.model import model_dump_json

from .. import dto
from .._pkg import asyva
from ..util.encoding import encode
from . import abstract


@dataclass(slots=True)
class PasswordService(abstract.VersionedSecretApplyMixin[dto.PasswordApplyDTO]):
    client: asyva.Client

    @override
    async def check_and_set(self, payload: dto.PasswordApplyDTO) -> None:
        """
        Performs `Check-and-Set` operation on a secret at path
        ``payload["spec"]["path"]``. The value is a generated password using the policy
        ``payload["spec"]["policyPath"]`` and the key is
        ``payload["spec"]["secretKey"]``

        Raises:
            PasswordPolicyNotFoundError: If the policy is not found.
            CASParameterMismatchError: If the provided version does not match the
                current version of the secret or is not incremented by one.
        """
        spec = payload.spec

        # may raise a PasswordPolicyNotFoundError
        value = await self.client.generate_password(policy_path=spec["policy_path"])

        # may raise a CASParameterMismatchError
        _ = await self.client.update_or_create_kvv2_secret(
            path=spec["path"],
            data={
                spec["secret_key"]: encode(
                    value=value.encode("utf-8"), encoding=spec["encoding"]
                )
            },
            cas=spec["version"] - 1,
            mount_path=spec["secrets_engine_path"],
        )
        _ = await self.client.update_or_create_metadata(
            mount_path=spec["secrets_engine_path"],
            path=spec["path"],
            custom_metadata={
                self.SNAPSHOT_LABEL: model_dump_json(camelize(payload.__dict__))
            },
        )
