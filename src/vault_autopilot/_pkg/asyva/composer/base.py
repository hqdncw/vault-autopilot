from dataclasses import dataclass
from typing import Any, Iterable

import aiohttp

HeadersContainer = dict[str, str]


@dataclass
class BaseComposer:
    """
    A base class for creating aiohttp ClientSession objects with default
    headers.

    Attributes:
        base_url (str): The base URL for the aiohttp ClientSession.
        skip_auto_headers (Iterator[str]): An iterable of header names to skip when
            creating the ClientSession.
    """

    base_url: str
    skip_auto_headers: Iterable[str] = (
        # https://developer.hashicorp.com/vault/api-docs#api-operations
        "Content-Type",
    )

    def compose_default_headers(self) -> HeadersContainer:
        """
        Composes default headers for the aiohttp ClientSession.

        Returns:
            Dict[str, str]: A dictionary of headers.
        """
        return {
            # add the X-Vault-Request header to all requests to protect against SSRF
            # vulnerabilities.
            # https://developer.hashicorp.com/vault/api-docs#the-x-vault-request-header
            "X-Vault-Request": "true"
        }

    def create(
        self, headers: HeadersContainer | None = None, **kwargs: Any
    ) -> aiohttp.ClientSession:
        """Creates an aiohttp ClientSession."""
        headers = headers or {}

        return aiohttp.ClientSession(
            base_url=self.base_url,
            headers=self.compose_default_headers().update(headers),
            skip_auto_headers=self.skip_auto_headers,
            **kwargs,
        )
