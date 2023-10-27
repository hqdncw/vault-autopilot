from pydantic.dataclasses import dataclass
from typing_extensions import TypedDict

from .._pkg.asyva.dto import password_policy
from . import base


class PasswordPolicySpec(TypedDict):
    path: str
    policy_params: password_policy.PasswordPolicy


@dataclass(slots=True)
class PasswordPolicyCreateDTO(base.BaseDTO):
    spec: PasswordPolicySpec
