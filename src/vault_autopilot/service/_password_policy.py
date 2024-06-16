from dataclasses import dataclass
from functools import cached_property
from typing import Any

from deepdiff import DeepDiff

from vault_autopilot._pkg.asyva.dto.password_policy import PasswordPolicy
from vault_autopilot.service.abstract import ResourceApplyMixin

from .. import dto
from .._pkg import asyva

Snapshot = PasswordPolicy


@dataclass
class PasswordPolicyService(ResourceApplyMixin[dto.PasswordPolicyApplyDTO, Snapshot]):
    client: asyva.Client

    def diff(
        self, payload: dto.PasswordPolicyApplyDTO, snapshot: Snapshot
    ) -> dict[str, Any]:
        return DeepDiff(
            snapshot,
            payload.spec["policy"],
            ignore_order=True,
            verbose_level=2,
        )

    async def build_snapshot(
        self, payload: dto.PasswordPolicyApplyDTO
    ) -> Snapshot | None:
        return await self.client.read_password_policy(payload.spec["path"])

    @cached_property
    def update_or_create_executor(self):
        return lambda payload: self.client.update_or_create_password_policy(
            path=payload.spec["path"], policy=payload.spec["policy"]
        )
