#! /bin/bash

. "./shell_scripts/activate_venv.sh"
sphinx-autobuild docs docs/_build/html --host 0.0.0.0
