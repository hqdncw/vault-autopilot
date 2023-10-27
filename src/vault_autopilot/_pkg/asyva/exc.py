from dataclasses import dataclass
from typing import Iterable, Optional

import aiohttp


@dataclass(slots=True)
class AsyvaError(Exception):
    """
    Base exception for all asyva errors.
    """

    message: str


@dataclass(slots=True)
class ConnectionRefusedError(AsyvaError):
    """
    Raised when the connection to the server is refused.

    This error is typically raised when the server does not accept the incoming
    connection, often due to a firewall rule or because the server is not listening on
    the specified port. Check the network connectivity and ensure that the server is
    running and accepting connections on the specified port.
    """

    host: str
    port: Optional[int]

    def __str__(self) -> str:
        return self.message.format(host=self.host, port=self.port)


@dataclass(slots=True)
class VaultAPIError(AsyvaError):
    """
    Base exception for all Vault API errors.
    """

    message: str
    errors: Optional[Iterable[str]] = None
    method: Optional[str] = None
    url: Optional[str] = None

    def __str__(self) -> str:
        msg = self.message

        if self.errors:
            msg += f". Errors: {', '.join(self.errors)}"
        if self.method:
            msg += f", on {self.method}"
        if self.url:
            msg += f", URL: {self.url}"
        return msg

    @classmethod
    async def from_response(
        cls, message: str, resp: aiohttp.ClientResponse
    ) -> "VaultAPIError":
        _STATUS_EXCEPTION_MAP = {
            400: InvalidRequestError,
            401: UnauthorizedError,
            403: ForbiddenError,
            404: InvalidPathError,
            429: RateLimitExceededError,
            500: InternalServerErrorError,
            501: VaultNotInitializedError,
            502: BadGatewayError,
            503: VaultDownError,
        }

        errors = await resp.json()
        return _STATUS_EXCEPTION_MAP.get(resp.status, UnexpectedError)(
            message=message,
            errors=errors.get("errors"),
            method=resp.method,
            url=str(resp.url),
        )


@dataclass(slots=True)
class InvalidRequestError(VaultAPIError):
    pass


@dataclass(slots=True)
class ForbiddenError(VaultAPIError):
    pass


@dataclass(slots=True)
class InvalidPathError(VaultAPIError):
    pass


@dataclass(slots=True)
class RateLimitExceededError(VaultAPIError):
    pass


@dataclass(slots=True)
class InternalServerErrorError(VaultAPIError):
    pass


@dataclass(slots=True)
class VaultNotInitializedError(VaultAPIError):
    pass


@dataclass(slots=True)
class VaultDownError(VaultAPIError):
    pass


@dataclass(slots=True)
class UnexpectedError(VaultAPIError):
    pass


@dataclass(slots=True)
class BadGatewayError(VaultAPIError):
    pass


@dataclass(slots=True)
class UnauthorizedError(VaultAPIError):
    """
    Raised when there is an issue with the authentication process when attempting to
    access the Vault API. This error can occur for a variety of reasons, including
    invalid credentials, missing credentials, or issues with the authentication backend.
    """


@dataclass(slots=True, kw_only=True)
class PasswordPolicyNotFoundError(VaultAPIError):
    """
    Raised when a password policy is not found.

    Attrs:
        policy_name: The name of the required password policy.
    """

    policy_name: str

    def __str__(self) -> str:
        return self.message.format(policy_name=self.policy_name)


@dataclass(slots=True, kw_only=True)
class CASParameterMismatchError(VaultAPIError):
    """
    Raised when modifying a Vault secret fails due to a problem with the Check
    And Set (CAS) parameter.

    Attributes:
        message: A human-readable description of the error.
        secret: The path of the secret that was affected by the error.
        provided_cas: The value of the CAS parameter that the client set.
        required_cas: The value of the CAS parameter that the server requires.

    References:
        See the HashiCorp documentation on Vault's CAS parameter for more information:
        https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#cas.
    """

    secret_path: str
    provided_cas: Optional[int] = None
    required_cas: Optional[int] = None

    def __str__(self) -> str:
        return self.message.format(
            secret_path=self.secret_path,
            provided_cas=self.provided_cas
            if isinstance(self.provided_cas, int)
            else "not set",
            required_cas=self.required_cas
            if isinstance(self.required_cas, int)
            else "unknown",
        )


@dataclass(slots=True, kw_only=True)
class IssuerNameTakenError(VaultAPIError):
    """
    Raised when attempting to create a new issuer with a name that is already in use.

    Attributes:
        message: A human-readable message describing the error.
        issuer_name: The name of the conflicting issuer.
        pki_mount_path:
            The path of the mounted Vault PKI where the creation attempt was made.
    """

    issuer_name: str
    pki_mount_path: str

    def __str__(self) -> str:
        return self.message.format(
            issuer_name=self.issuer_name, pki_mount_path=self.pki_mount_path
        )
