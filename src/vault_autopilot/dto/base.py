from typing import Any

import pydantic.alias_generators


class BaseModel(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel
    )


class MountSpec(BaseModel):
    mount: str


class PathSpec(BaseModel):
    path: str


class SecretSpec(MountSpec, PathSpec):
    """
    Provides a convenient way to work with secrets that need to be accessed through
    different secret engines and paths.
    """


class BaseDTO(BaseModel):
    @property
    def uid(self) -> int:
        return hash(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, BaseDTO):
            raise TypeError()
        return self.uid == other.uid


__all__ = [
    "BaseModel",
    "MountSpec",
    "PathSpec",
    "SecretSpec",
    "BaseDTO",
]
