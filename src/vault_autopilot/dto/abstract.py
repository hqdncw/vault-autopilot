from abc import abstractmethod
from typing import Annotated

import annotated_types
import pydantic.alias_generators
from pydantic import BaseModel, ConfigDict
from typing_extensions import TypedDict

from vault_autopilot.util.encoding import Encoding


class AbstractDTO(BaseModel):
    model_config = ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, extra="forbid"
    )

    @abstractmethod
    def absolute_path(self) -> str: ...


class SecretApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        secrets_engine: str
        path: str
        encoding: Annotated[Encoding, pydantic.Field(default="utf8")]

    spec: Spec


class VersionedSecretApplyDTO(SecretApplyDTO):
    class Spec(SecretApplyDTO.Spec):
        version: Annotated[int, annotated_types.Ge(1)]

    spec: Spec
