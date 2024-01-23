from typing import Annotated, Literal

import annotated_types
import pydantic
from typing_extensions import TypedDict

from . import abstract

StringEncodingType = Literal["base64", "utf8"]


class PasswordSpec(TypedDict):
    secret_engine: str
    path: str
    secret_key: str
    policy_path: str
    version: Annotated[int, annotated_types.Ge(1)]
    encoding: Annotated[StringEncodingType, pydantic.Field(default="utf8")]


class PasswordCheckOrSetDTO(abstract.AbstractDTO):
    kind: Literal["Password"]
    spec: PasswordSpec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secret_engine"], self.spec["path"]))
