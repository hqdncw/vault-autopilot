from typing import Any

import pydantic.alias_generators


class BaseModel(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel
    )


class BaseSpec(BaseModel):
    mount: str


class SecretSpec(BaseSpec):
    path: str

    def get_full_path(self) -> str:
        return "/".join((self.mount, self.path))


class BaseMetadata(BaseModel):
    name: str


class BaseDTO(BaseModel):
    kind: str
    metadata: BaseMetadata

    @property
    def uid(self) -> str:
        return ":".join((self.kind.lower(), self.metadata.name))

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, BaseDTO):
            raise TypeError()
        return self.uid == other.uid


__all__ = ["BaseModel", "BaseSpec", "SecretSpec", "BaseMetadata", "BaseDTO"]
