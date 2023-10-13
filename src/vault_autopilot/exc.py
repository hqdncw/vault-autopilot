from dataclasses import dataclass
from typing import Optional

import click


@dataclass
class ApplicationError(click.ClickException):
    """
    Signals that an error has occurred in the application.

    Provides an `exit_code` attribute for specifying a specific exit code, and a
    `message` attribute containing a human-readable description of the error.

    Allowed exit codes are defined in the Advanced Bash-Scripting Guide at
    <https://tldp.org/LDP/abs/html/exitcodes.html>. Note that user-defined exit codes
    are restricted to the range 64 - 113.

    Attributes:
        exit_code (int): The exit code to use when raising the exception.
        message (str): A brief description of the error.
    """

    exit_code = 1
    message: str


@dataclass
class ManifestValidationError(ApplicationError):
    """
    Raised when there is an issue with validating a given manifest file.
    """

    exit_code = 64
    filename: str
    linenumber: Optional[int] = None

    def format_message(self) -> str:
        return "Unable to decode %r: %s" % (self.filename, self.message)


@dataclass(kw_only=True)
class ManifestKindMismatchError(ManifestValidationError):
    """
    Raised when there're no matches for given kind.
    """

    provided_kind: str


@dataclass
class StdinInputCombinationError(ApplicationError):
    """Raised when user tries to combine the standard input with filenames (-f)."""

    def format_message(self) -> str:
        return f"Error applying manifests from standard input: {self.message}"


__all__ = ["ApplicationError", "StdinInputCombinationError"]
