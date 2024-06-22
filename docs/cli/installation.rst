.. _target installation:

############
Installation
############

Get started with Vault Autopilot CLI by choosing the installation method that
works best for you.

Installing with pip
===================

If you have Python >= 3.11 and pip installed on your system, you can install
Vault Autopilot CLI using the following command:

.. tab:: Linux

  .. prompt:: bash

    python3 -m pip install vault-autopilot[cli] && \
    vault-autopilot --help

.. tab:: MacOS

  .. prompt:: bash

    python3 -m pip install vault-autopilot[cli] && \
    vault-autopilot --help

.. tab:: Windows

  .. prompt:: powershell

    py -m pip install vault-autopilot[cli]
    py -m vault_autopilot --help

This will install the latest stable version of Vault Autopilot CLI and its
dependencies.

Installing with Docker
======================

You can also install Vault Autopilot CLI using Docker. This method is useful if
you don't want to install Python or pip on your system.

.. prompt:: bash

  docker run --rm hqdncw/vault-autopilot:latest --help

This will pull the latest Vault Autopilot CLI Docker image and run the
vault-autopilot command.

.. Vault Autopilot is also available as a GitHub Action. Read more about the setup
.. and configuration in our integrations guide.
