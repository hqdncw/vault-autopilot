import pathlib
from dataclasses import dataclass
from typing import NotRequired, TypedDict

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
    pass


@dataclass(slots=True)
class SecretVersionMismatchError(SecretIntegrityError):
    class Context(TypedDict):
        resource: VersionedSecretApplyDTO

    ctx: Context
