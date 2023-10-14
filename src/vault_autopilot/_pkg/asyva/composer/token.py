from dataclasses import dataclass

import pydantic

from . import base


@dataclass
class TokenComposer(base.BaseComposer):
    token: pydantic.SecretStr

    def compose_default_headers(
        self, data: base.HeadersContainer
    ) -> base.HeadersContainer:
        # https://developer.hashicorp.com/vault/docs/auth/token#via-the-api
        data.update({"X-Vault-Token": self.token.get_secret_value()})
        return super().compose_default_headers(data)
