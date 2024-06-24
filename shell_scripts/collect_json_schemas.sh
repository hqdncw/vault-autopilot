#!/usr/bin/env bash
#
. "./shell_scripts/activate_venv.sh"
python3 ./shell_scripts/collect_json_schemas.py "$@"
