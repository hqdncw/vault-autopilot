from typing import Annotated, Optional

import annotated_types
import pydantic


class CharsetRule(pydantic.BaseModel):
    charset: str = pydantic.Field(min_length=1)
    min_chars: Optional[Annotated[int, annotated_types.Ge(0)]] = None


class PasswordPolicy(pydantic.BaseModel):
    length: int = pydantic.Field(ge=4, le=100)
    rules: list[CharsetRule] = pydantic.Field(min_length=1)
