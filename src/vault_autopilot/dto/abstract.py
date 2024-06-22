from abc import abstractmethod
from typing import Annotated

import annotated_types
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from typing_extensions import TypedDict

from vault_autopilot.util.encoding import Encoding


class AbstractDTO(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, extra="forbid")

    kind: str

    @abstractmethod
    def absolute_path(self) -> str: ...


class SecretApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        secrets_engine_path: str
        path: str
        encoding: Annotated[Encoding, Field(default="utf8")]

    spec: Spec


class VersionedSecretApplyDTO(SecretApplyDTO):
    class Spec(SecretApplyDTO.Spec):
        version: Annotated[int, annotated_types.Ge(1)]

    spec: Spec
