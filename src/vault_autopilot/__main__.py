import logging
import pathlib
from typing import Optional

import click
import lazy_object_proxy
import pydantic
from ruamel import yaml
from ruamel.yaml.error import YAMLError

from vault_autopilot import _conf, util
from vault_autopilot._cli.apply import apply
from vault_autopilot._cli.exc import ConfigSyntaxError, ConfigValidationError

ConfigOption = Optional[pathlib.Path]

_loader = yaml.YAML(typ="safe")


def validate_config(ctx: click.Context, fn: ConfigOption) -> _conf.Settings:
    if fn is None:
        raise click.MissingParameter(
            param_type="option", param_hint="'-c' / '--config'", ctx=ctx
        )

    try:
        payload = _loader.load(fn.read_bytes())
    except YAMLError as ex:
        raise ConfigSyntaxError(
            "Invalid configuration file: Unable to decode %r: %s" % (str(fn), ex),
            ctx=ConfigSyntaxError.Context(filename=fn),
        ) from ex

    try:
        res = _conf.Settings(**payload)
    except pydantic.ValidationError as ex:
        # TODO: prevent token leakage in case of validation error
        raise ConfigValidationError(
            "Invalid configuration file: Failed to validate %s: %s"
            % (str(fn), util.model.convert_errors(ex)),
            ctx=ConfigValidationError.Context(filename=fn),
        ) from ex

    assert isinstance(res, _conf.Settings), "Expected %r, got %r" % (
        _conf.Settings.__name__,
        res,
    )
    return res


@click.group()
@click.option("-D", "--debug/--no-debug", default=False, help="Enable debug mode.")
@click.option(
    "-c",
    "--config",
    type=click.Path(
        dir_okay=False,
        exists=True,
        readable=True,
        path_type=pathlib.Path,
    ),
    help="Path to a YAML configuration file.",
)
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: ConfigOption) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
    )
    ctx.obj = lazy_object_proxy.Proxy(lambda: validate_config(ctx=ctx, fn=config))


if __name__ == "__main__":
    cli.add_command(apply)
    cli(auto_envvar_prefix="VAULT_AUTOPILOT")
