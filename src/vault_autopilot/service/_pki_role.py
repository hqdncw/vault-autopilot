from dataclasses import dataclass
from functools import cached_property
from os import path

from deepdiff import DeepDiff
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
    immutable_fields = (
        "root[[]'spec'[]][[]'name'[]]",
        "root[[]'spec'[]][[]'role'[]][[]'issuerRef'[]]",
    )

    @override
    def diff(self, payload: dto.PKIRoleApplyDTO, snapshot: Snapshot):
        return DeepDiff(
            dict(
                kind=payload.kind,
                spec=dict(
                    name=payload.spec["name"],
                    role=recursive_dict_filter(
                        {
                            **snapshot,
                            "issuer_ref": path.join(
                                payload.secrets_engine_ref(),
                                snapshot["issuer_ref"],
                            ),
                        },
                        payload.spec["role"],
                    ),
                ),
            ),
            payload.__dict__,
            ignore_order=True,
            verbose_level=2,
        )

    async def build_snapshot(self, payload: dto.PKIRoleApplyDTO) -> Snapshot | None:
        result = await self.client.read_pki_role(
            mount_path=payload.secrets_engine_ref(),
            name=payload.spec["name"],
        )
        return result.data if result is not None else None

    @cached_property
    def update_or_create_executor(self):
        return lambda payload: self.client.update_or_create_pki_role(
            mount_path=payload.secrets_engine_ref(),
            name=payload.spec["name"],
            issuer_ref=payload.spec["role"]["issuer_ref"].split("/")[-1],
            **model_dump(payload.spec["role"], exclude=("issuer_ref")),
        )
