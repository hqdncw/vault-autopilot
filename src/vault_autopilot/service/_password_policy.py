from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva
from . import _abstract


@dataclass(slots=True)
class PasswordPolicyService(_abstract.Service):
    client: asyva.Client

    async def push(self, payload: dto.BaseDTO) -> None:
        assert isinstance(payload, dto.PasswordPolicyDTO), "Expected %r, got %r" % (
            dto.PasswordPolicyDTO,
            payload,
        )
        await self.client.create_or_update_password_policy(
            path=payload.spec["path"],
            **util.pydantic.model_dump(
                payload.spec["policy_params"], exclude_unset=True
            ),
        )
