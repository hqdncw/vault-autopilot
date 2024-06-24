#!/usr/bin/env python3

import logging
import pathlib

import click
import lazy_object_proxy
import pydantic

from vault_autopilot._cli.commands.apply import apply
from vault_autopilot._cli.exc import ConfigSyntaxError, ConfigValidationError
from vault_autopilot._conf import Settings
from vault_autopilot.exc import Location
from vault_autopilot.util.model import convert_errors

ConfigOption = pathlib.Path | None


def validate_config(ctx: click.Context, fn: ConfigOption) -> Settings:
    payload = {}

    if fn is not None:
        from ruamel import yaml
        from ruamel.yaml.error import YAMLError

        _loader = yaml.YAML(typ="safe")

        try:
            payload = _loader.load(fn.read_bytes())
        except YAMLError as ex:
            raise ConfigSyntaxError(
                str(ex),
                ctx=ConfigSyntaxError.Context(loc=Location(filename=fn)),
            ) from ex

    try:
        res = Settings(**payload)
    except pydantic.ValidationError as ex:
        # TODO: prevent token leakage in case of validation error
        raise ConfigValidationError(str(convert_errors(ex))) from ex

    assert isinstance(res, Settings), "Expected %r, got %r" % (
        Settings.__name__,
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


cli.add_command(apply)

if __name__ == "__main__":
    cli(auto_envvar_prefix="VAULT_AUTOPILOT")
