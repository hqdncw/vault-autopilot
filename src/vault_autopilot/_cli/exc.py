from dataclasses import dataclass

import click

from ..exc import FileContext


@dataclass(slots=True)
class CLIError(click.ClickException):
    """
    Signals that an error has occurred in the application.

    Provides an `exit_code` attribute for specifying a specific exit code, and a
    `message` attribute containing a human-readable description of the error.

    See Also:
        Allowed exit codes are defined in the Advanced Bash-Scripting Guide at
        https://tldp.org/LDP/abs/html/exitcodes.html. Note that user-defined exit
        codes are restricted to the range 64 - 113.
    """

    message: str
    exit_code: int = 1


@dataclass(slots=True)
class ConfigError(CLIError):
    pass


@dataclass(slots=True, kw_only=True)
class ConfigSyntaxError(ConfigError):
    class Context(FileContext):
        pass

    ctx: Context


@dataclass(slots=True, kw_only=True)
class ConfigValidationError(ConfigError):
    class Context(FileContext):
        pass

    ctx: Context
