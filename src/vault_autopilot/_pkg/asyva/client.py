import functools
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Coroutine,
    Optional,
    ParamSpec,
    TypeVar,
    Union,
    overload,
)

import aiohttp
import jinja2
from typing_extensions import Unpack

from . import authenticator, composer, dto, exc, manager
from .dto import password_policy
from .manager import kvv2, pki

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
        except aiohttp.ClientConnectorError as ex:
            raise exc.ConnectionRefusedError(
                "The connection to the server {host}:{port} was refused - did you "
                "specify the right host or port?",
                host=ex.host,
                port=ex.port,
            ) from ex

    return wrapper


@dataclass
class Client:
    # conn: Optional[aiohttp.BaseConnector] = None
    # sslcontext: Optional[ssl.SSLContext] = None
    # proxy: Optional[str] = None
    # proxy_auth: Optional[aiohttp.BasicAuth] = None

    _env: jinja2.Environment = field(
        init=False,
        default_factory=lambda: jinja2.Environment(
            loader=jinja2.PackageLoader("vault_autopilot._pkg.asyva"), enable_async=True
        ),
    )
    _authn_sess: Optional[aiohttp.ClientSession] = field(init=False, default=None)
    _kvv2_mgr: manager.KVV2Manager = field(
        init=False, default_factory=manager.KVV2Manager
    )
    _pwd_policy_mgr: manager.PasswordPolicyManager = field(
        init=False, default_factory=manager.PasswordPolicyManager
    )
    _pki_mgr: manager.PKIManager = field(init=False, default_factory=manager.PKIManager)

    def __post_init__(self) -> None:
        self._render_password_policy = functools.partial(
            self._env.get_template("password_policy.jinja").render_async
        )

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
        # the secured endpoints
        self._authn_sess = composer.StandardComposer(
            base_url=base_url, token=token, namespace=namespace
        ).create()

        self._kvv2_mgr.configure(sess=self._authn_sess)
        self._pwd_policy_mgr.configure(sess=self._authn_sess)
        self._pki_mgr.configure(sess=self._authn_sess)

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self) -> None:
        if self._authn_sess:
            await self._authn_sess.__aexit__(None, None, None)

    @exception_handler
    @login_required
    async def update_or_create_secret(
        self, **payload: Unpack[dto.SecretCreateDTO]
    ) -> kvv2.UpdateOrCreateResult:
        """
        Creates a new secret or updates an existing one.

        Args:
            path: The path to the secret.
            data: The new value for the secret.
            cas: The expected version of the secret. If set to `None` (default) the
                write will be allowed. If set to `0` a write will only be allowed if the
                key doesn't exist as unset keys do not have any version information.
            mount_path: The path where the secret engine is mounted.

        Raises:
            CASParameterMismatchError: If the provided CAS value does not match the
                current version of the secret.

        References:
            https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-secret
        """
        return await self._kvv2_mgr.update_or_create(payload)

    @overload
    async def update_or_create_password_policy(self, path: str, policy: str) -> None:
        ...

    @overload
    async def update_or_create_password_policy(
        self, path: str, policy: password_policy.PasswordPolicy
    ) -> None:
        ...

    @exception_handler
    @login_required
    async def update_or_create_password_policy(
        self, path: str, policy: Union[password_policy.PasswordPolicy, str]
    ) -> None:
        """
        Creates a new password policy or updates an existing one.

        Args:
            path: Path to the password policy.
            policy: The policy to create or update. Can be a string containing the
                policy in HCL format or an instance of :class:`asyva.PasswordPolicy`.

        References:
            https://developer.hashicorp.com/vault/api-docs/system/policies-password#create-update-password-policy
        """
        await self._pwd_policy_mgr.update_or_create(
            path=path,
            policy=(
                await self._render_password_policy(policy=policy)
                if isinstance(policy, dict)
                else policy
            ),
        )

    @exception_handler
    @login_required
    async def generate_password(self, policy_path: str) -> str:
        """
        Generates a password from the specified existing password policy.

        References:
            https://developer.hashicorp.com/vault/api-docs/system/policies-password#generate-password-from-password-policy
        """
        return await self._pwd_policy_mgr.generate_password(policy_path=policy_path)

    @exception_handler
    @login_required
    async def generate_root(
        self, **payload: Unpack[dto.IssuerGenerateRootDTO]
    ) -> pki.GenerateRootResult:
        return await self._pki_mgr.generate_root(payload)

    @exception_handler
    @login_required
    async def generate_intermediate_csr(
        self, **payload: Unpack[dto.IssuerGenerateIntmdCSRDTO]
    ) -> pki.GenerateIntmdCSRResult:
        return await self._pki_mgr.generate_intmd_csr(payload)

    @exception_handler
    @login_required
    async def sign_intermediate(
        self, **payload: Unpack[dto.IssuerSignIntmdDTO]
    ) -> pki.SignIntmdResult:
        return await self._pki_mgr.sign_intmd(payload)

    @exception_handler
    @login_required
    async def set_signed_intermediate(
        self, **payload: Unpack[dto.IssuerSetSignedIntmdDTO]
    ) -> pki.SetSignedIntmdResult:
        return await self._pki_mgr.set_signed_intmd(payload)

    @exception_handler
    @login_required
    async def update_key(self, **payload: Unpack[dto.KeyUpdateDTO]) -> None:
        return await self._pki_mgr.update_key(payload)

    @exception_handler
    @login_required
    async def update_issuer(
        self, **payload: Unpack[dto.IssuerUpdateDTO]
    ) -> pki.UpdateResult:
        return await self._pki_mgr.update_issuer(payload)

    @exception_handler
    @login_required
    async def get_issuer(
        self, **payload: Unpack[dto.IssuerGetDTO]
    ) -> Optional[pki.GetResult]:
        return await self._pki_mgr.get_issuer(payload)

    @exception_handler
    @login_required
    async def update_or_create_pki_role(
        self, **payload: Unpack[dto.PKIRoleCreateDTO]
    ) -> None:
        return await self._pki_mgr.update_or_create_role(payload)
