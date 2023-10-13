import enum
from typing import Any, ClassVar

import pydantic

from . import base


class StringEncoding(enum.StrEnum):
    BASE64 = "base64"
    UTF8 = "utf8"


class PasswordSecretKeys(base.BaseModel):
    secret_key: str


class PasswordSpec(base.SecretSpec):
    path: str
    secret_keys: PasswordSecretKeys
    cas: int = pydantic.Field(ge=0)
    length: int = pydantic.Field(ge=0)
    use_specials: bool = False
    encoding: StringEncoding


class PasswordDTO(base.BaseDTO):
    __kind__: ClassVar = "Password"

    spec: PasswordSpec

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PasswordDTO):
            raise TypeError()
        return self.spec == other.spec
