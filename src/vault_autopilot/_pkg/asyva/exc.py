from collections.abc import Iterable
from dataclasses import dataclass
from typing import NotRequired

import aiohttp
from typing_extensions import TypedDict, override


@dataclass(slots=True)
class AsyvaError(Exception):
    """
    Base exception for all asyva errors.
    """

    class Context(TypedDict): ...

    message: str
    ctx: Context

    def format_message(self) -> str:
        return f"{self.message.format(ctx=self.ctx or {})}.\n\n{[self.ctx]}"

    @override
    def __str__(self) -> str:
        return self.format_message()


@dataclass(slots=True)
class VaultAPIError(AsyvaError):
    class Context(TypedDict):
        response: Iterable[str] | None
        http_method: str
        request_url: str

    @classmethod
    async def compose_context(cls, response: aiohttp.ClientResponse) -> "Context":
        return cls.Context(
            response=(await response.json() or {}),
            http_method=response.method,
            request_url=str(response.url),
        )

    @classmethod
    async def from_response(
        cls, message: str, response: aiohttp.ClientResponse
    ) -> "VaultAPIError":
        _STATUS_EXCEPTION_MAP: dict[int, type[VaultAPIError]] = {
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

        return _STATUS_EXCEPTION_MAP.get(response.status, UnexpectedError)(
            message=message, ctx=await cls.compose_context(response)
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
class ResourceNotFoundError(InvalidRequestError):
    """
    Raised when a resource is not found.
    """

    class Context(VaultAPIError.Context):
        """
        Attributes:
            path: The path of the resource that was not found.
            mount_path: The mount path of the resource that was not found
        """

        path: str
        mount_path: str

    ctx: Context


class PasswordPolicyNotFoundError(ResourceNotFoundError): ...


class IssuerNotFoundError(ResourceNotFoundError): ...


@dataclass(slots=True, kw_only=True)
class CASParameterMismatchError(InvalidRequestError):
    """
    Raised when modifying a Vault secret fails due to a problem with the Check
    And Set (CAS) parameter.

    References:
        See the HashiCorp documentation on Vault's CAS parameter for more information:
        <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#cas>.
    """

    class Context(VaultAPIError.Context):
        """
        Attributes:
            secret: The path to the secret that the client attempted to modify. It
                follows the standard format of ``mount_path/path``, where ``mount_path``
                is the mount point of the secrets engine, and path leads to the specific
                secret within that engine.
            provided_cas: The value of the CAS parameter that the client set.
            required_cas: The value of the CAS parameter that the server requires.
        """

        secret: str
        provided_cas: NotRequired[int]
        required_cas: NotRequired[int]

    ctx: Context


@dataclass(slots=True, kw_only=True)
class ResourcePathInUseError(InvalidRequestError):
    """
    Raised when attempting to create a new resource with a path that is already in use.
    """

    class Context(VaultAPIError.Context):
        """
        Attributes:
            path_collision: The path of the conflicting resource.
            mount_path: The mount path where the resource was attempted to be created.
        """

        path_collision: str
        mount_path: str

    ctx: Context


class IssuerNameTakenError(ResourcePathInUseError): ...


class SecretsEnginePathInUseError(ResourcePathInUseError): ...
