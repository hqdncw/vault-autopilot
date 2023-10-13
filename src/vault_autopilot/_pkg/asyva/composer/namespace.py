from dataclasses import dataclass
from typing import Optional

from . import base


@dataclass
class NamespaceComposer(base.BaseComposer):
    namespace: Optional[str] = None

    def compose_default_headers(
        self, data: base.HeadersContainer
    ) -> base.HeadersContainer:
        # https://developer.hashicorp.com/vault/api-docs#namespaces
        if self.namespace:
            data.update({"X-Vault-Namespace": self.namespace})
        return super().compose_default_headers(data)
