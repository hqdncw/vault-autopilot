from typing import Annotated, Literal, NotRequired

from pydantic import Field
from typing_extensions import TypedDict

from .._pkg.asyva.dto.secrets_engine import (
    KvV2Options,
    SecretsEngineConfig,
)
from .abstract import AbstractDTO


class AbstractEngineOptions(TypedDict):
    description: NotRequired[str]
    config: NotRequired[SecretsEngineConfig]
    local: NotRequired[bool]
    seal_wrap: NotRequired[bool]
    external_entropy_access: NotRequired[bool]


class KvV2EngineOptions(AbstractEngineOptions):
    type: Literal["kv-v2"]
    options: NotRequired[KvV2Options]
    cas_required: NotRequired[bool]
    delete_version_after: NotRequired[str]
    max_versions: NotRequired[int]


class PKIEngineOptions(AbstractEngineOptions):
    type: Literal["pki"]


class SecretsEngineApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        path: str
        engine: Annotated[
            PKIEngineOptions | KvV2EngineOptions, Field(discriminator="type")
        ]

    kind: Literal["SecretsEngine"] = "SecretsEngine"
    spec: Spec

    def absolute_path(self) -> str:
        return self.spec["path"]
