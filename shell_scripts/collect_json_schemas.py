#!/usr/bin/env python3

import json
from pathlib import Path

from pydantic.json_schema import model_json_schema
from vault_autopilot import dto
from vault_autopilot._conf import Settings


def execute(output_dir: str):
    for filename, builder in {
        Path(output_dir) / "issuer.json": dto.IssuerApplyDTO,
        Path(output_dir) / "secrets_engine.json": dto.SecretsEngineApplyDTO,
        Path(output_dir) / "pki_role.json": dto.PKIRoleApplyDTO,
        Path(output_dir) / "password.json": dto.PasswordApplyDTO,
        Path(output_dir) / "password_policy.json": dto.PasswordPolicyApplyDTO,
        Path(output_dir) / "ssh_key.json": dto.SSHKeyApplyDTO,
        Path(output_dir) / "configuration.json": Settings,
    }.items():
        filename.write_text(json.dumps(model_json_schema(builder), indent=2))
        print("generated", filename)


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(
        prog="collect_json_schemas",
        description="Collects JSON schemas from entire application to a given folder.",
    )
    parser.add_argument("output_dir")
    args = parser.parse_args()

    execute(output_dir=args.output_dir)
