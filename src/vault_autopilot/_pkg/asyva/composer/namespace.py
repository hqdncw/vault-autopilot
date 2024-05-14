from dataclasses import dataclass

from .base import BaseComposer, HeadersContainer


@dataclass
class NamespaceComposer(BaseComposer):
    namespace: str | None = None

    def compose_default_headers(
        self,
    ) -> HeadersContainer:
        headers = super().compose_default_headers()

        # https://developer.hashicorp.com/vault/api-docs#namespaces
        if self.namespace:
            headers.setdefault("X-Vault-Namespace", self.namespace)

        return headers
