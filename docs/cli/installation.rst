.. _target installation:

############
Installation
############

This guide will walk you through the process of installing Vault Autopilot CLI
using various methods, ensuring you can choose the one that best suits your
needs.

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

.. Vault Autopilot is also available as a GitHub Action. Read more about the setup
.. and configuration in our integrations guide.
