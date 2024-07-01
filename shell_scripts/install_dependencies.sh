#!/usr/bin/env bash

. "./shell_scripts/activate_venv.sh"
pip install .["$@"]
