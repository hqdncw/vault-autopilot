from typing import Annotated, Optional

import annotated_types
from typing_extensions import TypedDict


class CharsetRule(TypedDict):
    charset: Annotated[str, annotated_types.MinLen(1)]
    min_chars: Optional[Annotated[int, annotated_types.Ge(0)]]


class PasswordPolicy(TypedDict):
    length: Annotated[int, annotated_types.Ge(4), annotated_types.Le(100)]
    rules: Annotated[tuple[CharsetRule, ...], annotated_types.MinLen(1)]
