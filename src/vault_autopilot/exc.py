import pathlib
from dataclasses import dataclass
from typing import Any, NotRequired, TypedDict

from typing_extensions import override

from .dto.abstract import AbstractDTO

__all__ = (
    "ApplicationError",
    "ManifestError",
    "ManifestValidationError",
    "ManifestSyntaxError",
    "ResourceIntegrityError",
    "ResourceImmutFieldError",
    "SnapshotMismatchError",
    "SecretVersionMismatchError",
)


@dataclass(slots=True)
class ApplicationError(Exception):
    class Context(TypedDict): ...

    message: str
    ctx: Context | None

    def format_message(self) -> str:
        return self.message.format(ctx=self.ctx or {})

    @override
    def __str__(self) -> str:
        return self.format_message()


class Location(TypedDict):
    filename: pathlib.Path
    line: NotRequired[int]
    col: NotRequired[int]
    offset: NotRequired[int]


@dataclass(slots=True)
class ManifestError(ApplicationError): ...


@dataclass(slots=True)
class ManifestSyntaxError(ManifestError):
    """
    Raised when there is an issue with parsing a given manifest file.
    """

    class Context(TypedDict):
        loc: Location

    ctx: Context

    @override
    def format_message(self) -> str:
        return "Decoding failed for manifest file %r.\n\n%s" % (
            str(self.ctx["loc"]["filename"]),
            self.message,
        )


@dataclass(slots=True)
class ManifestValidationError(ManifestError):
    """
    Raised when there is an issue with validating a given manifest file.
    """

    class Context(TypedDict):
        loc: Location

    ctx: Context

    @override
    def format_message(self) -> str:
        return "Validation failed for manifest file %r.\n\n%s" % (
            str(self.ctx["loc"]["filename"]),
            self.message,
        )


@dataclass(slots=True)
class ResourceIntegrityError(ApplicationError):
    """Raised when a resource fails integrity check."""

    class Context(TypedDict):
        """
        Attributes:
            resource: The resource that failed the integrity check.
        """

        resource: AbstractDTO

    ctx: Context

    @override
    def format_message(self) -> str:
        return "Resource %r integrity check failed.\n\n%s" % (
            str(self.ctx["resource"].absolute_path()),
            self.message.format(ctx=self.ctx),
        )


@dataclass(slots=True)
class ResourceImmutFieldError(ResourceIntegrityError):
    """
    Raised when an attempt is made to modify an immutable field in a resource.

    This error indicates that a field in a resource is marked as immutable, but an
    attempt was made to change its value.
    """

    class Context(ResourceIntegrityError.Context):
        field_name: str
        diff: dict[str, Any]

    ctx: Context


@dataclass(slots=True)
class SnapshotMismatchError(ResourceIntegrityError):
    """
    Raised when the snapshot of a resource does not match the expected structure.

    This error usually occurs when you modify some fields of the manifest object but
    forget to bump the version field.
    """

    class Context(ResourceIntegrityError.Context):
        """
        Attributes:
            diff: A dictionary describing the structural differences between the
                expected and actual resource structures.
        """

        diff: dict[str, Any]

    ctx: Context


@dataclass(slots=True)
class SecretVersionMismatchError(ResourceIntegrityError):
    """
    Raised when the version of a secret does not match the expected version.

    This error usually occurs when the secret version in the manifest does not match
    the version of the secret stored in the system. This can happen if the secret
    has been updated since the last time the manifest was applied.
    """
