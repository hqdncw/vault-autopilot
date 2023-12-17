from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import password_policy
from . import abstract


class PasswordPolicySpec(TypedDict):
    path: str
    policy_params: password_policy.PasswordPolicy


class PasswordPolicyCreateDTO(abstract.AbstractDTO):
    kind: Literal["PasswordPolicy"]
    spec: PasswordPolicySpec
