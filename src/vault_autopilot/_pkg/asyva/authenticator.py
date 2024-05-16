import abc
import http
import logging
import pathlib
from dataclasses import dataclass
from typing import Literal
from typing_extensions import override

import aiohttp
import pydantic

from . import constants, exc

__all__ = "AbstractAuthenticator", "KubernetesAuthenticator", "TokenAuthenticator"


logger = logging.getLogger(__name__)


def read_jwt(fn: str) -> str:
    return pathlib.Path(fn).read_text()


@dataclass(slots=True)
class AbstractAuthenticator(abc.ABC):
    """
    An abstract class that defines the interface for authenticating with the Vault Auth
    Method.

    See Also:
        https://developer.hashicorp.com/vault/docs/auth
    """

    @abc.abstractmethod
    async def authenticate(self, sess: aiohttp.ClientSession) -> pydantic.SecretStr:
        """Returns a string value representing the client token obtained through
        successful authentication."""


@dataclass(slots=True)
class KubernetesAuthenticator(AbstractAuthenticator):
    mount_path: str
    role: str
    jwt: pydantic.SecretStr

    @override
    async def authenticate(self, sess: aiohttp.ClientSession) -> pydantic.SecretStr:
        """
        References:
            https://developer.hashicorp.com/vault/docs/auth/kubernetes#via-the-api
        """
        resp = await sess.post(
            f"/v1/auth/{self.mount_path}/login",
            json={"jwt": self.jwt.get_secret_value(), "role": self.role},
        )

        if resp.status == http.HTTPStatus.OK:
            return pydantic.SecretStr(str((await resp.json())["auth"]["client_token"]))

        logger.debug(await resp.json())
        raise await exc.VaultAPIError.from_response(
            "Failed to authenticate with kubernetes", resp
        )


@dataclass(slots=True)
class TokenAuthenticator(AbstractAuthenticator):
    token: pydantic.SecretStr
    source: Literal["directvalue", "filebasedvalue"] = "directvalue"

    @override
    async def authenticate(self, sess: aiohttp.ClientSession) -> pydantic.SecretStr:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/auth/token#lookup-a-token-self
        """
        # The token is either a string or a file containing the string.
        match self.source:
            case "directvalue":
                token = self.token.get_secret_value()
            case "filebasedvalue":
                token = read_jwt(self.token.get_secret_value())
            case _:
                raise NotImplementedError(
                    "Invalid token source specified: %r. Supported sources include "
                    "'directvalue' and `'filebasedvalue'." % self.source
                )

        resp = await sess.get(
            "/v1/auth/token/lookup-self",
            headers={constants.AUTHORIZATION_HEADER: token},
        )

        match resp.status:
            case http.HTTPStatus.OK:
                return self.token
            case http.HTTPStatus.FORBIDDEN:
                raise exc.UnauthorizedError(
                    "The token you provided is invalid or has expired. Please "
                    "ensure that your Vault credentials are correct and try again.",
                )
            case _:
                pass

        logger.debug(await resp.json())
        raise await exc.VaultAPIError.from_response(
            "Failed to authenticate with provided token", resp
        )
