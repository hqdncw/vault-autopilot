from dataclasses import dataclass
from functools import cached_property

from deepdiff import DeepDiff
from humps import camelize
from typing_extensions import override

from vault_autopilot._pkg.asyva.dto.pki_role import PKIRoleFields
from vault_autopilot.service.abstract import ResourceApplyMixin
from vault_autopilot.util.model import model_dump, recursive_dict_filter

from .. import dto
from .._pkg import asyva

Snapshot = PKIRoleFields


@dataclass
class PKIRoleService(ResourceApplyMixin[dto.PKIRoleApplyDTO, Snapshot]):
    client: asyva.Client

    @override
    def diff(self, payload: dto.PKIRoleApplyDTO, snapshot: Snapshot):
        return DeepDiff(
            dto.PKIRoleApplyDTO(
                kind=payload.kind,
                spec=dto.PKIRoleApplyDTO.Spec(
                    **camelize(
                        dict(
                            **model_dump(
                                payload.spec, include=("secrets_engine_path", "name")
                            ),
                            role=recursive_dict_filter(snapshot, payload.spec["role"]),
                        )
                    )
                ),
            ),
            payload,
            ignore_order=True,
            verbose_level=2,
        )

    async def build_snapshot(self, payload: dto.PKIRoleApplyDTO) -> Snapshot | None:
        result = await self.client.read_pki_role(
            name=payload.spec["name"], mount_path=payload.spec["secrets_engine_path"]
        )
        return result.data if result is not None else None

    @cached_property
    def update_or_create_executor(self):
        return lambda payload: self.client.update_or_create_pki_role(
            name=payload.spec["name"],
            mount_path=payload.spec["secrets_engine_path"],
            **model_dump(payload.spec["role"]),
        )
