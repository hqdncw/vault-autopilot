from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva


@dataclass(slots=True)
class PKIRoleService:
    client: asyva.Client

    async def update_or_create(self, payload: dto.PKIRoleApplyDTO) -> None:
        await self.client.update_or_create_pki_role(
            name=payload.spec["name"],
            mount_path=payload.spec["secret_engine"],
            **util.model.model_dump(payload.spec["role"]),
        )
