from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva


@dataclass(slots=True)
class PasswordPolicyService:
    client: asyva.Client

    async def create_or_update(self, payload: dto.PasswordPolicyCreateDTO) -> None:
        await self.client.create_or_update_password_policy(
            path=payload.spec["path"],
            **util.pydantic.model_dump(
                payload.spec["policy_params"], exclude_unset=True
            ),
        )
