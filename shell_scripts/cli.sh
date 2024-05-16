#! /bin/bash

# This script is designed to activate a Python virtual environment for running
# the Vault Autopilot CLI. It's especially handy for developers who want to
# test the CLI directly from the source files.

export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
source ./.venv/bin/activate
python3 src/vault_autopilot "$@"
