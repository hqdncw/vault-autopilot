import pathlib
from dataclasses import dataclass
from typing import Any, NotRequired, TypedDict

from typing_extensions import override

from .dto.abstract import VersionedSecretApplyDTO

__all__ = (
    "ApplicationError",
    "ManifestError",
    "ManifestValidationError",
    "ManifestSyntaxError",
    "SecretIntegrityError",
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
class ManifestError(ApplicationError):
    pass


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
class SecretIntegrityError(ApplicationError):
    """Raised when a secret fails integrity check."""

    class Context(TypedDict):
        """
        Attributes:
            resource: The secret resource that failed the integrity check.
        """

        resource: VersionedSecretApplyDTO

    ctx: Context

    @override
    def format_message(self) -> str:
        return "Resource %r integrity check failed.\n\n%s" % (
            str(self.ctx["resource"].absolute_path()),
            self.message.format(ctx=self.ctx),
        )


@dataclass(slots=True)
class SnapshotMismatchError(SecretIntegrityError):
    """
    Raised when the snapshot of a secret does not match the expected structure.

    This error usually occurs when you modify some fields of the manifest object but
    forget to bump the version field.
    """

    class Context(SecretIntegrityError.Context):
        """
        Attributes:
            diff: A dictionary describing the structural differences between the
                expected and actual secret structures.
        """

        diff: dict[str, Any]

    ctx: Context


@dataclass(slots=True)
class SecretVersionMismatchError(SecretIntegrityError):
    """
    Raised when the version of a secret does not match the expected version.

    This error usually occurs when the secret version in the manifest does not match
    the version of the secret stored in the system. This can happen if the secret
    has been updated since the last time the manifest was applied.
    """
