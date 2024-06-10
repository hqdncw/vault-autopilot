from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import password_policy
from .abstract import AbstractDTO


class PasswordPolicySpec(TypedDict):
    path: str
    policy: password_policy.PasswordPolicy


class PasswordPolicyApplyDTO(AbstractDTO):
    kind: Literal["PasswordPolicy"] = "PasswordPolicy"
    spec: PasswordPolicySpec

    def absolute_path(self) -> str:
        return self.spec["path"]
