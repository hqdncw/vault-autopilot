from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import password_policy
from .abstract import AbstractDTO


class PasswordPolicyApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        path: str
        policy: password_policy.PasswordPolicy

    kind: Literal["PasswordPolicy"] = "PasswordPolicy"
    spec: Spec

    def absolute_path(self) -> str:
        return self.spec["path"]
