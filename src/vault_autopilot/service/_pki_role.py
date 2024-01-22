from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva


@dataclass(slots=True)
class PKIRoleService:
    client: asyva.Client

    async def create_or_update(self, payload: dto.PKIRoleCheckOrSetDTO) -> None:
        await self.client.create_or_update_pki_role(
            name=payload.spec["name"],
            mount_path=payload.spec["secret_engine"],
            **util.model.model_dump(payload.spec["role"]),
        )
