import enum
from typing import Any

import pydantic

from . import base


class StringEncoding(enum.StrEnum):
    BASE64 = "base64"
    UTF8 = "utf8"


class PasswordSecretKeys(base.BaseModel):
    secret_key: str


class PasswordSpec(base.SecretSpec):
    secret_keys: PasswordSecretKeys
    policy_path: str
    cas: int = pydantic.Field(ge=0)
    encoding: StringEncoding


class PasswordDTO(base.BaseDTO):
    spec: PasswordSpec

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PasswordDTO):
            raise TypeError()
        return self.spec.path == other.spec.path
