from dataclasses import dataclass

from .. import dto
from .._pkg import asyva


@dataclass(slots=True)
class PasswordPolicyService:
    client: asyva.Client

    async def create_or_update(self, payload: dto.PasswordPolicyInitializeDTO) -> None:
        await self.client.create_or_update_password_policy(
            path=payload.spec["path"], policy=payload.spec["policy"]
        )
