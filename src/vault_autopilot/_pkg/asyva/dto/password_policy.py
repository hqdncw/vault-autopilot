from typing import Annotated

import annotated_types
import pydantic
from typing_extensions import NotRequired, TypedDict


class CharsetRule(TypedDict):
    charset: Annotated[str, annotated_types.MinLen(1)]
    min_chars: NotRequired[Annotated[int, annotated_types.Ge(0)]]


class PasswordPolicy(TypedDict):
    length: Annotated[int, annotated_types.Ge(4), annotated_types.Le(100)]
    rules: Annotated[tuple[CharsetRule, ...], pydantic.Field(min_length=1)]


class PasswordPolicyCreateDTO(TypedDict):
    path: str
    policy: str


class PasswordPolicyGenerateDTO(TypedDict):
    policy_path: str
