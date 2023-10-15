from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva
from ..dto.password import StringEncoding
from . import _abstract


def encode(value: str, encoding: str) -> str:
    match encoding:
        case StringEncoding.BASE64:
            return util.encoding.base64_encode(value)
        case StringEncoding.UTF8:
            return value
        case _:
            raise NotImplementedError("Unknown string encoding present")


@dataclass(frozen=True, slots=True)
class PasswordService(_abstract.Service):
    client: asyva.Client

    async def push(self, payload: dto.BaseDTO) -> None:
        assert isinstance(payload, dto.PasswordDTO), "Expected %r, got %r" % (
            dto.PasswordDTO,
            payload,
        )

        try:
            value = await self.client.generate_password(
                policy_path=payload.spec.policy_path
            )
        except asyva.exc.PolicyNotFoundError as ex:
            # TODO: Instead of just saying "Policy not found", provide the user with a
            #  more informative error message that includes the line number in the
            #  manifest file where the policy path was defined.
            raise ex

        await self.client.create_or_update_secret(
            path=payload.spec.path,
            data={
                payload.spec.secret_keys.secret_key: encode(
                    value=value,
                    encoding=payload.spec.encoding,
                )
            },
            cas=payload.spec.cas,
            mount_path=payload.spec.mount,
        )
