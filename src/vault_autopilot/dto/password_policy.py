from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import password_policy
from . import abstract


class PasswordPolicySpec(TypedDict):
    path: str
    policy: password_policy.PasswordPolicy


class PasswordPolicyApplyDTO(abstract.AbstractDTO):
    kind: Literal["PasswordPolicy"] = "PasswordPolicy"
    spec: PasswordPolicySpec

    def absolute_path(self) -> str:
        return self.spec["path"]
