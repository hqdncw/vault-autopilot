import pathlib
from dataclasses import dataclass
from typing import NotRequired, TypedDict
from typing_extensions import override

from . import dto

__all__ = (
    "ApplicationError",
    "ManifestValidationError",
    "ManifestSyntaxError",
)


@dataclass(slots=True)
class ApplicationError(Exception):
    message: str

    def format_message(self) -> str:
        return self.message

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

    message: str
    ctx: Context

    @override
    def format_message(self) -> str:
        return "Decoding failed '%s': %s" % (self.ctx["loc"]["filename"], self.message)


@dataclass(slots=True)
class ManifestValidationError(ManifestError):
    """
    Raised when there is an issue with validating a given manifest file.
    """

    class Context(TypedDict):
        loc: Location

    message: str
    ctx: Context

    @override
    def format_message(self) -> str:
        return "Validation failed '%s': %s" % (self.ctx["loc"]["filename"], self.message)


@dataclass(slots=True)
class SecretIntegrityError(ApplicationError):
    pass


@dataclass(slots=True)
class SecretVersionMismatchError(SecretIntegrityError):
    class Context(TypedDict):
        resource: dto.VersionedSecretApplyDTO

    ctx: Context
