from dataclasses import dataclass

from .. import dto
from .._pkg import asyva
from . import _abstract


@dataclass(frozen=True, slots=True)
class PasswordPolicyService(_abstract.Service):
    client: asyva.Client

    async def push(self, payload: dto.BaseDTO) -> None:
        assert isinstance(payload, dto.PasswordPolicyDTO), "Expected %r, got %r" % (
            dto.PasswordPolicyDTO,
            payload,
        )
        await self.client.create_or_update_password_policy(
            path=payload.spec.path, policy=payload.spec
        )
