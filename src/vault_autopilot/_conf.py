from typing import Annotated, Literal

import pydantic.alias_generators
from pydantic import Field
from pydantic.dataclasses import dataclass
from typing_extensions import TypedDict

from ._pkg import asyva

_config = pydantic.ConfigDict(
    alias_generator=pydantic.alias_generators.to_camel, extra="forbid"
)


@dataclass(slots=True, config=_config, kw_only=True)
class KubernetesAuthMethod(asyva.KubernetesAuthenticator):
    method: Literal["kubernetes"]


@dataclass(slots=True, config=_config, kw_only=True)
class TokenAuthMethod(asyva.TokenAuthenticator):
    method: Literal["token"]


class VaultSecretStorage(TypedDict):
    type: Literal["kvv1-secret"]
    secrets_engine_path: Annotated[
        str, Field(default="hqdncw.github.io/vault-autopilot/user-data")
    ]
    snapshots_secret_path: Annotated[str, Field(default="snapshots")]


@dataclass(slots=True, config=_config)
class Settings:
    base_url: str
    storage: VaultSecretStorage
    auth: KubernetesAuthMethod | TokenAuthMethod = pydantic.Field(
        discriminator="method"
    )
    default_namespace: str = ""
