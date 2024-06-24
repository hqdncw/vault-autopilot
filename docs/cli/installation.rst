############
Installation
############

Get started with Vault Autopilot CLI by choosing the installation method that
works best for you.

Installing with pip
===================

If you have Python >= 3.11 and pip installed on your system, you can install
Vault Autopilot CLI using the following command:

.. prompt:: bash

  pip install --user vault-autopilot[cli] && \
  vault-autopilot --help

This will install the latest stable version of Vault Autopilot CLI and its
dependencies.

.. warning::

  The ``--user`` is important, that ensures you install it in your user's
  directory and not in the global system.

  If you installed it in the global system (e.g. with sudo) you could install a
  version of a library (e.g. a sub-dependency) that is incompatible with your
  system.

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
