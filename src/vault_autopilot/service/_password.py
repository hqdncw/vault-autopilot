from dataclasses import dataclass
from typing_extensions import override

from .. import dto, util
from .._pkg import asyva
from ..dto.password import StringEncodingType
from . import abstract


def encode(value: str, encoding: StringEncodingType) -> str:
    match encoding:
        case "base64":
            return util.encoding.base64_encode(value)
        case "utf8":
            return value


@dataclass(slots=True)
class PasswordService(abstract.VersionedSecretApplyMixin):
    client: asyva.Client

    @override
    async def check_and_set(self, payload: dto.PasswordApplyDTO) -> None:
        """
        Sets a password secret with the given payload and version, while ensuring that
        the version is valid and the secret is updated correctly.

        Specifically, this method will only set the secret if the following conditions
        are met:
            - The provided version is greater than the current secret version.
            - The provided version is not more than 1 greater than the current version.

        If the provided version does not meet these conditions, a
        :class:`CASParameterMismatchError` will be raised.

        Raises:
            PasswordPolicyNotFoundError: If the policy is not found.
            CASParameterMismatchError: If the provided version does not match the
                current version of the secret or is not incremented by one.
        """
        spec = payload.spec

        # may raise a PasswordPolicyNotFoundError
        value = await self.client.generate_password(policy_path=spec["policy_path"])

        # may raise a CASParameterMismatchError
        _ = await self.client.update_or_create_secret(
            path=spec["path"],
            data={spec["secret_key"]: encode(value=value, encoding=spec["encoding"])},
            cas=spec["version"] - 1,
            mount_path=spec["secret_engine"],
        )
