from typing import Any, Optional

import pydantic
import pydantic.alias_generators
from pydantic.dataclasses import dataclass

from ._pkg import asyva


@dataclass(slots=True)
class AuthMethodSelector:
    kubernetes: Optional[asyva.KubernetesAuthenticator] = None
    token: Optional[asyva.TokenAuthenticator] = None

    @pydantic.model_validator(mode="before")
    @classmethod
    def mutually_exclusive(cls, data: dict[str, Any]) -> dict[str, Any]:
        if isinstance(data, dict):
            params = (
                isinstance(data.get("kubernetes"), dict),
                isinstance(data.get("token"), dict),
            )
            if not any(params) or all(params):
                raise ValueError(
                    "input must include a mapping key that is either 'kubernetes' "
                    " or 'token'"
                )
        return data

    def get_authenticator(
        self,
    ) -> asyva.KubernetesAuthenticator | asyva.TokenAuthenticator:
        if self.token:
            return self.token
        if self.kubernetes:
            return self.kubernetes
        raise RuntimeError("Authentication method not selected")


@dataclass(
    config=pydantic.ConfigDict(alias_generator=pydantic.alias_generators.to_camel)
)
class Settings:
    auth: AuthMethodSelector
    base_url: str
    default_namespace: str = ""
