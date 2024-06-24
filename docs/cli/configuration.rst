#############
Configuration
#############

To use the Vault Autopilot CLI, you need to provide credentials to access your
Vault server. This can be done through either a configuration file or
environment variables.


Configuration File
==================

If you choose to use a configuration file, simply specify the file's path along
with the :ref:`--config<target config_flag>` flag before running any command. For
example:

.. code:: bash

  $ vault-autopilot --config "vault-autopilot.yaml" apply [ARGS]...

This tells the CLI to use the settings in your ``vault-autopilot.yaml`` file
when executing the apply command. Just be sure to replace
``vault-autopilot.yaml`` with the actual path to your file.


Config File Example
-------------------

Here's an example of what your configuration file might look like:

.. code:: yaml

  baseUrl: "https://localhost:8200"
  auth:
    method: token
    token: "<TOKEN>"
  storage:
    type: "kvv1-secret"


Environment Variables
=====================

Alternatively, you can set environment variables to configure the Vault
Autopilot CLI.

Precedence
----------

If both a configuration file and environment variables are provided, the
environment variables will take precedence. This allows you to override
specific settings in your configuration file with environment variables.

For example, if your ``vault-autopilot.yaml`` file contains:

.. code:: yaml

  baseUrl: "https://localhost:8200"
  auth:
    method: token
    token: "<TOKEN>"
  storage:
    type: "kvv1-secret"

And you set the following environment variable:

.. prompt:: bash

  export AUTH__TOKEN="<NEW_TOKEN>"

The ``NEW_TOKEN`` value will be used instead of the value in the
``vault-autopilot.yaml`` file.

Configuration keys
==================

This section documents all configuration keys, presented in `JSON schema`_
format:

.. _JSON schema: https://json-schema.org/

.. include:: ../_static/schemas/configuration.json
  :literal:
