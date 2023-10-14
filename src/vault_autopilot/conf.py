from typing import Any, Optional

import pydantic.alias_generators

from vault_autopilot._pkg import asyva


class BaseModel(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_snake
    )


class AuthMethodSelector(BaseModel):
    kubernetes: Optional[asyva.KubernetesAuthenticator] = None
    token: Optional[asyva.TokenAuthenticator] = None

    @pydantic.model_validator(mode="before")
    @classmethod
    def mutually_exclusive(cls, data: Any) -> Any:
        if isinstance(data, dict):
            options = data.get("kubernetes"), data.get("token")
            if not any(options):
                raise ValueError("either 'kubernetes' or 'token' must be provided")
            if all(options):
                raise ValueError("only one of 'kubernetes' and 'token' can be provided")
        return data

    def get_authenticator(
        self,
    ) -> asyva.KubernetesAuthenticator | asyva.TokenAuthenticator:
        if self.token:
            return self.token
        if self.kubernetes:
            return self.kubernetes
        raise RuntimeError("Authentication method not selected")


class Settings(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_snake
    )

    auth: AuthMethodSelector
    base_url: str = "http://localhost:8200"
    namespace: Optional[str] = None
