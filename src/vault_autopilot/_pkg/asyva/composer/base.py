from dataclasses import dataclass
from typing import Any, Optional

import aiohttp

HeadersContainer = dict[str, str]


@dataclass
class BaseComposer:
    """
    This class is a helpful tool for streamlining the process of creating HTTP sessions
    with HashiCorp Vault. It makes it easier to construct HTTP requests to Vault by
    taking care of the required headers, such as the `X-Vault-Request` header, so you
    don't have to worry about them.

    :param base_url: The base URL of the Vault server.
    :param skip_auto_headers: A list of header names that will be skipped when
        autogenerating the request headers.

    .. note::
        You can provide a custom `headers` dictionary to the `create()` method to
        include additional information in the request.
    """

    base_url: str
    skip_auto_headers = (
        # https://developer.hashicorp.com/vault/api-docs#api-operations
        "Content-Type",
    )

    def compose_default_headers(self, data: HeadersContainer) -> HeadersContainer:
        """Composes the default headers for a Vault request."""
        # add the X-Vault-Request header to all requests to protect against SSRF
        # vulnerabilities.
        # https://developer.hashicorp.com/vault/api-docs#the-x-vault-request-header
        data.update({"X-Vault-Request": "true"})
        return data

    def create(
        self, headers: Optional[HeadersContainer] = None, **kwargs: Any
    ) -> aiohttp.ClientSession:
        """Creates a new `aiohttp.ClientSession` instance configured for Vault
        requests."""
        headers, default_headers = headers or {}, self.compose_default_headers({})
        assert not (
            inter := any(x in default_headers.keys() for x in headers.keys())
        ), ("You aren't allowed to override default headers!\n%r" % inter)
        return aiohttp.ClientSession(
            base_url=self.base_url,
            headers={**headers, **default_headers},
            skip_auto_headers=self.skip_auto_headers.__iter__(),
            **kwargs,
        )
