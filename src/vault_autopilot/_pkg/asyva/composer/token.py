from dataclasses import dataclass

import pydantic

from .base import BaseComposer, HeadersContainer


@dataclass(kw_only=True)
class TokenComposer(BaseComposer):
    token: pydantic.SecretStr

    def compose_default_headers(
        self,
    ) -> HeadersContainer:
        headers = super().compose_default_headers()

        # https://developer.hashicorp.com/vault/docs/auth/token#via-the-api
        headers.setdefault("X-Vault-Token", self.token.get_secret_value())

        return headers
