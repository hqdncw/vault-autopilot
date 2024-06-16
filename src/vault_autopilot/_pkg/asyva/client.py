import functools
from collections.abc import Awaitable, Coroutine
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ParamSpec,
    Self,
    TypeVar,
    overload,
)

import aiohttp
import jinja2
from typing_extensions import Unpack

from . import authenticator, composer, dto
from .dto.password_policy import PasswordPolicy
from .manager import kvv2, password_policy, pki, system_backend
from .util.hcl import deseralize_password_policy

P = ParamSpec("P")
T = TypeVar("T")


def login_required(func: Callable[P, T]) -> Callable[P, T]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        assert isinstance((client := args[0]), Client), (
            "Expected instance of %r, got %r" % (Client, client)
        )
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
            raise ConnectionRefusedError(
                (
                    'The connection to the server "%s:%s" was refused - did you '
                    "specify the right host or port?"
                )
                % (ex.host, ex.port)
            ) from ex

    return wrapper


@dataclass(slots=True)
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
    _authn_sess: aiohttp.ClientSession | None = field(init=False, default=None)
    _kvv2_mgr: kvv2.KVV2Manager = field(init=False, default_factory=kvv2.KVV2Manager)
    _pwd_policy_mgr: password_policy.PasswordPolicyManager = field(
        init=False, default_factory=password_policy.PasswordPolicyManager
    )
    _pki_mgr: pki.PKIManager = field(init=False, default_factory=pki.PKIManager)
    _sb_mgr: system_backend.SystemBackendManager = field(
        init=False, default_factory=system_backend.SystemBackendManager
    )
    _render_password_policy: functools.partial[Coroutine[Any, Any, str]] = field(
        init=False
    )

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
        namespace: str | None = None,
    ) -> Self:
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
        self._sb_mgr.configure(sess=self._authn_sess)

        return self

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
        return await self._kvv2_mgr.update_or_create(**payload)

    @overload
    async def update_or_create_password_policy(
        self, path: str, policy: str
    ) -> None: ...

    @overload
    async def update_or_create_password_policy(
        self, path: str, policy: PasswordPolicy
    ) -> None: ...

    @exception_handler
    @login_required
    async def update_or_create_password_policy(
        self, path: str, policy: PasswordPolicy | str
    ) -> None:
        """
        Creates a new password policy or updates an existing one.

        Args:
            path: Path to the password policy.
            policy: The policy to create or update. Can be a string containing the
                policy in HCL format or an instance of :class:`asyva.PasswordPolicy`.

        References:
            <https://developer.hashicorp.com/vault/api-docs/system/policies-password#create-update-password-policy>
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
    async def read_password_policy(self, path: str) -> PasswordPolicy | None:
        """
        Reads an existing password policy.

        Args:
            path: Path to the password policy.

        Returns:
            The password policy in HCL format as a string.

        References:
            <https://developer.hashicorp.com/vault/api-docs/system/policies-password#read-password-policy>
        """
        result = await self._pwd_policy_mgr.read(path)

        return (
            deseralize_password_policy(result.data["policy"])
            if result is not None
            else None
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
        return await self._pki_mgr.generate_root(**payload)

    @exception_handler
    @login_required
    async def generate_intermediate_csr(
        self, **payload: Unpack[dto.IssuerGenerateIntmdCSRDTO]
    ) -> pki.GenerateIntmdCSRResult:
        return await self._pki_mgr.generate_intmd_csr(**payload)

    @exception_handler
    @login_required
    async def sign_intermediate(
        self, **payload: Unpack[dto.IssuerSignIntmdDTO]
    ) -> pki.SignIntmdResult:
        return await self._pki_mgr.sign_intmd(**payload)

    @exception_handler
    @login_required
    async def set_signed_intermediate(
        self, **payload: Unpack[dto.IssuerSetSignedIntmdDTO]
    ) -> pki.SetSignedIntmdResult:
        return await self._pki_mgr.set_signed_intmd(**payload)

    @exception_handler
    @login_required
    async def update_pki_key(self, **payload: Unpack[dto.KeyUpdateDTO]) -> None:
        return await self._pki_mgr.update_key(**payload)

    @exception_handler
    @login_required
    async def update_issuer(
        self, **payload: Unpack[dto.IssuerUpdateDTO]
    ) -> pki.IssuerUpdateResult:
        return await self._pki_mgr.update_issuer(**payload)

    @exception_handler
    @login_required
    async def read_issuer(
        self, **payload: Unpack[dto.IssuerReadDTO]
    ) -> pki.IssuerReadResult | None:
        return await self._pki_mgr.read_issuer(**payload)

    @exception_handler
    @login_required
    async def update_or_create_pki_role(
        self, **payload: Unpack[dto.PKIRoleCreateDTO]
    ) -> None:
        return await self._pki_mgr.update_or_create_role(**payload)

    @login_required
    async def read_pki_role(
        self, **payload: Unpack[dto.PKIRoleReadDTO]
    ) -> pki.RoleReadResult | None:
        return await self._pki_mgr.read_role(**payload)

    @exception_handler
    @login_required
    async def enable_secrets_engine(
        self, **payload: Unpack[dto.SecretsEngineEnableDTO]
    ) -> None:
        return await self._sb_mgr.enable_secrets_engine(**payload)

    @exception_handler
    @login_required
    async def configure_secrets_engine(
        self, **payload: Unpack[dto.SecretsEngineConfigureDTO]
    ) -> None:
        return await self._kvv2_mgr.configure_secret_engine(**payload)

    @exception_handler
    @login_required
    async def tune_mount_configuration(
        self, **payload: Unpack[dto.SecretsEngineTuneMountConfigurationDTO]
    ) -> None:
        return await self._sb_mgr.tune_mount_configuration(**payload)

    @exception_handler
    @login_required
    async def read_mount_configuration(
        self, **payload: Unpack[dto.SecretsEngineReadDTO]
    ) -> system_backend.ReadMountConfigurationResult | None:
        return await self._sb_mgr.read_mount_configuration(**payload)

    @exception_handler
    @login_required
    async def read_kv_configuration(
        self, **payload: Unpack[dto.SecretsEngineReadDTO]
    ) -> kvv2.ReadConfigurationResult | None:
        return await self._kvv2_mgr.read_configuration(**payload)

    @exception_handler
    @login_required
    async def read_kv_metadata(
        self, **payload: Unpack[dto.SecretReadDTO]
    ) -> kvv2.ReadMetadataResult:
        return await self._kvv2_mgr.read_metadata(**payload)

    @exception_handler
    @login_required
    async def update_or_create_metadata(
        self, **payload: Unpack[dto.SecretUpdateOrCreateMetadata]
    ) -> None:
        return await self._kvv2_mgr.update_or_create_metadata(**payload)
