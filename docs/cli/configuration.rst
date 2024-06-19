.. _target configuration:

#############
Configuration
#############

To use the Vault Autopilot CLI, you need to provide credentials to access your
Vault server. This is done through a simple configuration file that specifies
the necessary authentication details.

Setting Up Your Configuration
=============================

To use your custom configuration file with the Vault Autopilot CLI, simply
specify the file's path along with the :ref:`--config<target commands>` flag
before running any command. For example:

.. code:: bash

   $ vault-autopilot --config config.yaml apply

This tells the CLI to use the settings in your ``config.yaml`` file when
executing the apply command. Just be sure to replace ``config.yaml`` with the
actual path to your file.

Config File Example
===================

Here's an example of what your configuration file might look like:

.. code:: yaml

   baseUrl: "https://localhost:8200"
   auth:
     method: token
     token: "<REDACTED>"


Configuration keys
==================

This section documents all configuration keys, presented in `JSON schema`_
format:

.. _JSON schema: https://json-schema.org/

.. include:: ../_static/schemas/configuration.json
   :literal:
