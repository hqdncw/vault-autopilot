from abc import abstractmethod
from typing import Annotated, Literal

import annotated_types
import pydantic.alias_generators
from pydantic import BaseModel, ConfigDict
from typing_extensions import TypedDict

StringEncodingType = Literal["base64", "utf8"]


class AbstractDTO(BaseModel):
    model_config = ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, extra="forbid"
    )

    @abstractmethod
    def absolute_path(self) -> str: ...


class SecretApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        encoding: Annotated[StringEncodingType, pydantic.Field(default="utf8")]

    spec: Spec


class VersionedSecretApplyDTO(SecretApplyDTO):
    class Spec(SecretApplyDTO.Spec):
        version: Annotated[int, annotated_types.Ge(1)]

    spec: Spec
