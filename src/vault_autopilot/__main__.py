import logging
import pathlib
from typing import Any, Optional

import click
import lazy_object_proxy
import pydantic
import yaml.error

from vault_autopilot import conf, exc
from vault_autopilot.cli.apply import apply
from vault_autopilot.helper.pydantic import convert_errors


def validate_config(payload: dict[str, Any]) -> conf.Settings:
    if not payload:
        # TODO: print example usage
        raise click.ClickException("Missing option '-c' / '--config'.")

    try:
        res = conf.Settings(**payload)
        assert isinstance(res, conf.Settings), "Expected %r, got %r" % (
            conf.Settings.__name__,
            res,
        )
        return res
    except pydantic.ValidationError as ex:
        # TODO: prevent token leaking in case of validation error
        raise exc.ApplicationError(
            "Improperly configured: %s" % convert_errors(ex)
        ) from ex


@click.group()
@click.option("-D", "--debug/--no-debug", default=False, help="Enable debug mode")
@click.option(
    "-c",
    "--config",
    type=click.Path(
        dir_okay=False,
        exists=True,
        resolve_path=True,
        readable=True,
        path_type=pathlib.Path,
    ),  # type: ignore
    help="Location of a client config file",
)
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: Optional[pathlib.Path] = None) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
    )

    try:
        data = yaml.load(config.read_bytes() if config else bytes(), yaml.SafeLoader)
    except yaml.error.MarkedYAMLError as ex:
        assert config is not None
        raise exc.ApplicationError(
            "Error parsing %r: %s" % (click.format_filename(str(config)), ex)
        ) from ex

    ctx.obj = lazy_object_proxy.Proxy(lambda: validate_config(payload=data))


if __name__ == "__main__":
    cli.add_command(apply)
    cli(auto_envvar_prefix="VAULT_AUTOPILOT")
