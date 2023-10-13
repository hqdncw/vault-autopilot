import logging
import pathlib
from typing import Optional

import click
import lazy_object_proxy
import pydantic
import yaml.error

from vault_autopilot import conf, exc
from vault_autopilot.cli.apply import apply
from vault_autopilot.helper.pydantic import convert_errors

ConfigOption = Optional[pathlib.Path]


def validate_config(fn: ConfigOption) -> conf.Settings:
    if fn is None:
        # TODO: print usage examples
        raise click.ClickException("Missing option '-c' / '--config'.")

    try:
        payload = yaml.load(fn.read_bytes() if fn else bytes(), yaml.SafeLoader)
    except yaml.error.MarkedYAMLError as ex:
        raise exc.ManifestValidationError(str(ex), filename=str(fn)) from ex

    try:
        res = conf.Settings.model_validate(payload)
    except pydantic.ValidationError as ex:
        # TODO: prevent token leakage in case of validation error
        raise exc.ManifestValidationError(str(convert_errors(ex)), filename=str(fn))

    assert isinstance(res, conf.Settings), "Expected %r, got %r" % (
        conf.Settings.__name__,
        res,
    )
    return res


@click.group()
@click.option("-D", "--debug/--no-debug", default=False, help="Enable debug mode")
@click.option(
    "-c",
    "--config",
    type=click.Path(  # type: ignore
        dir_okay=False,
        exists=True,
        resolve_path=True,
        readable=True,
        path_type=pathlib.Path,  # pyright: ignore
    ),
    help="Path to a YAML configuration file",
)
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: ConfigOption = None) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
    )
    ctx.obj = lazy_object_proxy.Proxy(lambda: validate_config(fn=config))


if __name__ == "__main__":
    cli.add_command(apply)
    cli(auto_envvar_prefix="VAULT_AUTOPILOT")
