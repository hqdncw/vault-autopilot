from dataclasses import dataclass
from typing import Any

from deepdiff import DeepDiff

from vault_autopilot._pkg.asyva.dto.password_policy import PasswordPolicy
from vault_autopilot.service.abstract import ApplyResult

from .. import dto
from .._pkg import asyva


@dataclass(slots=True)
class PasswordPolicyService:
    client: asyva.Client

    async def diff(
        self, payload: dto.PasswordPolicyApplyDTO, snapshot: PasswordPolicy
    ) -> dict[str, Any]:
        return DeepDiff(
            snapshot,
            payload.spec["policy"],
            ignore_order=True,
            verbose_level=2,
        )

    async def apply(self, payload: dto.PasswordPolicyApplyDTO) -> ApplyResult:
        snapshot = await self.client.read_password_policy(payload.spec["path"])

        is_create = snapshot is None
        is_update = bool(await self.diff(payload, snapshot)) if not is_create else False

        if not (is_create or is_update):
            return ApplyResult(status="verify_success")

        try:
            await self.client.update_or_create_password_policy(
                path=payload.spec["path"], policy=payload.spec["policy"]
            )
        except Exception as exc:
            return ApplyResult(
                status="create_error" if is_create else "update_error", errors=(exc,)
            )

        if is_create:
            return ApplyResult(status="create_success")
        else:
            return ApplyResult(status="update_success")
