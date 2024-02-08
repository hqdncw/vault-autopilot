from dataclasses import dataclass

from .. import dto
from .._pkg import asyva


@dataclass(slots=True)
class PasswordPolicyService:
    client: asyva.Client

    async def update_or_create(self, payload: dto.PasswordPolicyApplyDTO) -> None:
        await self.client.update_or_create_password_policy(
            path=payload.spec["path"], policy=payload.spec["policy"]
        )
