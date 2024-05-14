from typing import Literal

import pydantic.alias_generators
from pydantic.dataclasses import dataclass

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


@dataclass(slots=True, config=_config)
class Settings:
    base_url: str
    auth: KubernetesAuthMethod | TokenAuthMethod = pydantic.Field(
        discriminator="method"
    )
    default_namespace: str = ""
