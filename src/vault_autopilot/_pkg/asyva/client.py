import asyncio
import functools
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional, ParamSpec, TypeVar

import aiohttp

from . import authenticator, composer, exc, manager

P = ParamSpec("P")
T = TypeVar("T")


def login_required(func: Callable[P, T]) -> Callable[P, T]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        assert isinstance(
            (client := args[0]), Client
        ), "Expected instance of %r, got %r" % (Client, client)
        assert (
            client.is_authenticated
        ), "The Vault client must be authenticated before calling this method."
        return func(*args, **kwargs)

    return wrapper


def exception_handler(
    func: Callable[P, Awaitable[T]],
) -> Callable[P, Coroutine[Any, Any, T]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await func(*args, **kwargs)
        except exc.VaultAPIError as ex:
            raise ex
        except aiohttp.ClientConnectorError as ex:
            raise exc.ConnectionRefusedError(ex.host, ex.port) from ex
        except Exception as ex:
            raise ex

    return wrapper


@dataclass
class Client:
    # conn: Optional[aiohttp.BaseConnector] = None
    # sslcontext: Optional[ssl.SSLContext] = None
    # proxy: Optional[str] = None
    # proxy_auth: Optional[aiohttp.BasicAuth] = None

    _authn_sess: Optional[aiohttp.ClientSession] = field(init=False, default=None)
    _kv_mgr: manager.KvManager = field(init=False, default_factory=manager.KvManager)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._authn_sess)

    @exception_handler
    async def authenticate(
        self,
        base_url: str,
        authn: authenticator.AbstractAuthenticator,
        namespace: Optional[str] = None,
    ) -> None:
        assert (
            not self.is_authenticated
        ), "Attempting to authenticate while already authenticated"

        # Obtain the authorization bearer token
        async with composer.BaseComposer(base_url=base_url).create() as sess:
            token = await authn.authenticate(sess=sess)

        # Provide the managers with an authenticated session, allowing them to access
        # the Vault instance
        self._authn_sess = composer.StandardComposer(
            base_url=base_url, token=token, namespace=namespace
        ).create()

        self._kv_mgr.configure(sess=self._authn_sess)

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self) -> None:
        if self._authn_sess:
            await self._authn_sess.__aexit__(None, None, None)

        # Zero-sleep to allow underlying connections to close
        # https://docs.aiohttp.org/en/stable/client_advanced.html?highlight=sleep#graceful-shutdown
        await asyncio.sleep(0)

    @login_required
    @exception_handler
    async def create_or_update_secret(
        self,
        path: str,
        data: dict[str, str],
        mount_path: str,
        cas: Optional[int] = None,
    ) -> None:
        """
        Create or update a secret at the given path with the given data.

        Args:
            path: The path to the secret.
            data: The new value for the secret.
            cas:
                The expected version of the secret. If set to `None` the write will be
                allowed. If set to `0` a write will only be allowed if the key doesn't
                exist as unset keys do not have any version information.
            mount_path: The path where the secret engine is mounted.

        Raises:
            SecretNotFoundError: If the secret does not exist.
            CASParameterMismatchError:
                If the provided CAS value does not match the current version of the
                secret.

        Notes:
            <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-secret>
        """
        await self._kv_mgr.create_or_update(
            path=path, data=data, cas=cas, mount_path=mount_path
        )
