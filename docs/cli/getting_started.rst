###############
Getting Started
###############

Welcome to Vault Autopilot CLI, a powerful tool for managing your Vault
resources with ease and precision. This guide will walk you through the process
of getting started with Vault Autopilot CLI, from setting up your Vault server
to applying your first manifest.


Prerequisites
=============

Before you start, make sure you have Docker installed to run the Vault
Autopilot CLI in a container (or check our :ref:`Installation` page for
alternative options).


Starting a Vault Server Instance
================================

If you haven't already, launch your Vault Server Instance. You can do this by
running the following command:

.. prompt:: bash

   docker run --cap-add=IPC_LOCK -d --name=dev-vault \
   -e VAULT_DEV_ROOT_TOKEN_ID="insecure-dev-only-token" \
   -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
   --network host \
   hashicorp/vault server -dev

Output:

.. container:: toggle, toggle-hidden

   .. code:: bash

      ==> Vault server configuration:

      Administrative Namespace:
                   Api Address: http://0.0.0.0:8200
                           Cgo: disabled
               Cluster Address: https://0.0.0.0:8201
         Environment Variables: GOTRACEBACK, HOME, HOSTNAME, NAME, PATH, PWD, SHLVL, VAULT_DEV_LISTEN_ADDRESS, VAULT_DEV_ROOT_TOKEN_ID, VERSION
                    Go Version: go1.21.9
                    Listener 1: tcp (addr: "0.0.0.0:8200", cluster address: "0.0.0.0:8201", disable_request_limiter: "false", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
                     Log Level:
                         Mlock: supported: true, enabled: false
                 Recovery Mode: false
                       Storage: inmem
                       Version: Vault v1.16.2, built 2024-04-22T16:25:54Z
                   Version Sha: c6e4c2d4dc3b0d57791881b087c026e2f75a87cb

      ==> Vault server started! Log data will stream in below:
      2024-05-15T16:38:33.411Z [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
      2024-05-15T16:38:33.412Z [INFO]  incrementing seal generation: generation=1
      2024-05-15T16:38:33.412Z [WARN]  no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set
      2024-05-15T16:38:33.416Z [INFO]  core: Initializing version history cache for core
      2024-05-15T16:38:33.416Z [INFO]  events: Starting event system
      2024-05-15T16:38:33.417Z [INFO]  core: security barrier not initialized
      2024-05-15T16:38:33.417Z [INFO]  core: security barrier initialized: stored=1 shares=1 threshold=1

      2024-05-15T16:38:33.419Z [INFO]  core: post-unseal setup starting
      2024-05-15T16:38:33.426Z [INFO]  core: loaded wrapping token key
      2024-05-15T16:38:33.426Z [INFO]  core: successfully setup plugin runtime catalog
      2024-05-15T16:38:33.426Z [INFO]  core: successfully setup plugin catalog: plugin-directory=""
      2024-05-15T16:38:33.430Z [INFO]  core: no mounts; adding default mount table
      2024-05-15T16:38:33.431Z [INFO]  core: successfully mounted: type=cubbyhole version="v1.16.2+builtin.vault" path=cubbyhole/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.433Z [INFO]  core: successfully mounted: type=system version="v1.16.2+builtin.vault" path=sys/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.434Z [INFO]  core: successfully mounted: type=identity version="v1.16.2+builtin.vault" path=identity/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.436Z [INFO]  core: successfully mounted: type=token version="v1.16.2+builtin.vault" path=token/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.437Z [INFO]  rollback: Starting the rollback manager with 256 workers
      2024-05-15T16:38:33.439Z [INFO]  rollback: starting rollback manager
      2024-05-15T16:38:33.439Z [INFO]  core: restoring leases
      2024-05-15T16:38:33.442Z [INFO]  expiration: lease restore complete
      2024-05-15T16:38:33.445Z [INFO]  identity: entities restored
      2024-05-15T16:38:33.445Z [INFO]  identity: groups restored
      2024-05-15T16:38:33.446Z [INFO]  core: Recorded vault version: vault version=1.16.2 upgrade time="2024-05-15 16:38:33.446289491 +0000 UTC" build date=2024-04-22T16:25:54Z
      2024-05-15T16:38:33.447Z [INFO]  core: post-unseal setup complete
      2024-05-15T16:38:33.447Z [INFO]  core: root token generated
      2024-05-15T16:38:33.447Z [INFO]  core: pre-seal teardown starting
      2024-05-15T16:38:33.448Z [INFO]  rollback: stopping rollback manager
      2024-05-15T16:38:33.448Z [INFO]  core: pre-seal teardown complete
      2024-05-15T16:38:33.449Z [INFO]  core.cluster-listener.tcp: starting listener: listener_address=0.0.0.0:8201
      2024-05-15T16:38:33.449Z [INFO]  core.cluster-listener: serving cluster requests: cluster_listen_address=[::]:8201
      2024-05-15T16:38:33.450Z [INFO]  core: post-unseal setup starting
      2024-05-15T16:38:33.450Z [INFO]  core: loaded wrapping token key
      2024-05-15T16:38:33.450Z [INFO]  core: successfully setup plugin runtime catalog
      2024-05-15T16:38:33.450Z [INFO]  core: successfully setup plugin catalog: plugin-directory=""
      2024-05-15T16:38:33.451Z [INFO]  core: successfully mounted: type=system version="v1.16.2+builtin.vault" path=sys/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.451Z [INFO]  core: successfully mounted: type=identity version="v1.16.2+builtin.vault" path=identity/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.451Z [INFO]  core: successfully mounted: type=cubbyhole version="v1.16.2+builtin.vault" path=cubbyhole/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.451Z [INFO]  core: successfully mounted: type=token version="v1.16.2+builtin.vault" path=token/ namespace="ID: root. Path: "
      2024-05-15T16:38:33.452Z [INFO]  rollback: Starting the rollback manager with 256 workers
      2024-05-15T16:38:33.452Z [INFO]  rollback: starting rollback manager
      2024-05-15T16:38:33.452Z [INFO]  core: restoring leases
      2024-05-15T16:38:33.452Z [INFO]  identity: entities restored
      2024-05-15T16:38:33.452Z [INFO]  identity: groups restored
      2024-05-15T16:38:33.452Z [INFO]  expiration: lease restore complete
      2024-05-15T16:38:33.452Z [INFO]  core: post-unseal setup complete
      2024-05-15T16:38:33.452Z [INFO]  core: vault is unsealed
      2024-05-15T16:38:33.453Z [INFO]  expiration: revoked lease: lease_id=auth/token/root/ha14ff1dded5c609be17b12b7202501f362461d72f7a171fa097f3d7082846171
      2024-05-15T16:38:33.456Z [INFO]  core: successful mount: namespace="" path=secret/ type=kv version="v0.17.0+builtin"
      WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
      and starts unsealed with a single unseal key. The root token is already
      authenticated to the CLI, so you can immediately begin using Vault.

      You may need to set the following environment variables:

          $ export VAULT_ADDR='http://0.0.0.0:8200'

      The unseal key and root token are displayed below in case you want to
      seal/unseal the Vault or re-authenticate.

      Unseal Key: zlksaGI337oTvPMz2DU7QmuAXlI26vbXQwKvgycMa5M=
      Root Token: insecure-dev-only-token

      Development mode should NOT be used in production installations!


Creating a Bash Alias
=====================

Instead of installing the Vault Autopilot CLI locally, you can use a Docker
container to get started quickly. Here's an example bash alias that runs the
Vault Autopilot CLI within a Docker container, with some initial configuration:

.. prompt:: bash

  alias vault-autopilot=' \
  docker run -i --rm --network host \
  -e BASEURL="http://localhost:8200" \
  -e AUTH__METHOD="token" \
  -e AUTH__TOKEN="insecure-dev-only-token" \
  -e STORAGE__TYPE="kvv1-secret" \
  hqdncw/vault-autopilot:latest' "$@"

It uses token-based authentication with a default token
``insecure-dev-only-token`` and stores data in the ``kvv1-secret`` storage
type. You can always override these values as needed.

.. note::

  For a comprehensive list of all available environment variables, please refer
  to the :ref:`Configuration` page.


Verify the Alias Setup
======================

Before moving forward, make sure your alias is set up correctly by running the
``--help`` command. This will ensure that the Vault Autopilot CLI is
functioning as expected.

.. prompt:: bash

  vault-autopilot --help

If everything is set up correctly, you should see the help menu with
information on available commands, options, and flags. If you encounter any
issues, double-check your alias setup and try again.


Defining a Manifest File
========================

A manifest is a YAML file that defines the desired state of your Vault
resources. Create a new file called ``manifest.yaml`` with the following content:

.. code:: yaml

  kind: SecretsEngine
  spec:
    path: kv
    engine:
      # the type of the secrets engine (e.g., kv-v2 for version 2 of the key-value
      # secrets engine)
      type: kv-v2
  ---
  kind: PasswordPolicy
  spec:
    path: example
    policy:
      length: 32
      rules:
        - charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          minChars: 1
        - charset: "abcdefghijklmnopqrstuvwxyz"
          minChars: 1
        - charset: "0123456789"
          minChars: 1
        - charset: "!@#$%^&*"
          minChars: 1
  ---
  kind: Password
  spec:
    path: hello
    # path to the secrets engine declared before
    secretsEnginePath: kv
    # path to the password policy declared before
    policyPath: example
    # the key for which the value will be automatically generated using the given
    # password policy
    secretKey: foo
    version: 1


Applying the Manifest to Your Vault Server
==========================================

To apply the manifest to your Vault server, run the following command:

.. prompt:: bash

   vault-autopilot apply < manifest.yaml

Output:

.. code:: bash

  [+] Applying manifests (0.0184 seconds) FINISHED
   => Creating SecretsEngine 'kv'... done
   => Creating PasswordPolicy 'example'... done
   => Creating Password 'kv/hello'... done
  Thanks for choosing Vault Autopilot!

Vault Autopilot CLI will parse the manifest and apply the necessary changes to
your Vault server.

.. TODO: You can verify the changes by running vault-autopilot status.


Inspecting the Vault State
==========================

After running the ``vault-autopilot apply`` command, you can verify that the
configuration has been applied correctly by checking the Vault password
policies and secrets.

.. code:: bash

  $ docker exec -i dev-vault sh -- <<EOF
  export VAULT_ADDR=http://127.0.0.1:8200
  vault login -- token="insecure-dev-only-token"
  vault kv get kv/hello
  vault kv get sys/policies/password/example
  EOF

Output:

.. container:: toggle, toggle-hidden

 .. code:: bash

   Success! You are now authenticated. The token information displayed below
   is already stored in the token helper. You do NOT need to run "vault login"
   again. Future Vault requests will automatically use this token.

   Key                  Value
   ---                  -----
   token                insecure-dev-only-token
   token_accessor       ENSsKMk79TAyur8E0NozrJde
   token_duration       ∞
   token_renewable      false
   token_policies       ["root"]
   identity_policies    []
   policies             ["root"]
   == Secret Path ==
   kv/data/hello

   ======= Metadata =======
   Key                Value
   ---                -----
   created_time       2024-06-17T10:41:19.822630332Z
   custom_metadata    map[hqdncw.github.io/vault-autopilot/snapshot:{"spec":{"secretsEnginePath":"kv","path":"hello","encoding":"utf8","version":1,"secretKey":"foo","policyPath":"example"},"kind":"Password"}]
   deletion_time      n/a
   destroyed          false
   version            1

   === Data ===
   Key    Value
   ---    -----
   foo    irtrxWdGu966VM3mA$#Z0yyawp4c2N!s
   ===== Data =====
   Key       Value
   ---       -----
   policy    length = 32
   rule "charset" {
     charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
     min-chars = 1
   }
   rule "charset" {
     charset = "abcdefghijklmnopqrstuvwxyz"
     min-chars = 1
   }
   rule "charset" {
     charset = "0123456789"
     min-chars = 1
   }
   rule "charset" {
     charset = "!@#$%^&*"
     min-chars = 1
   }

This will display a summary of the current state of your Vault resources,
including the secret and password policy defined in your manifest.


Managing Configuration Updates
==============================

Let's say you want to beef up your password policy by requiring longer
passwords. Previously, the policy required a password of exactly 32 characters,
but now you want to bump that up to 64. Easy peasy! Just update the
``manifest.yaml`` file like this:

.. code:: yaml

  ...
  kind: PasswordPolicy
  spec:
    path: example
    policy:
      length: 64  # increased from 32 to 64
      rules:
        - charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          minChars: 1
        - charset: "abcdefghijklmnopqrstuvwxyz"
          minChars: 1
        - charset: "0123456789"
          minChars: 1
        - charset: "!@#$%^&*"
          minChars: 1
  ...

After modifying the manifest file, run the ``vault-autopilot apply <
manifest.yaml`` command again to apply the changes to your Vault server:

.. code:: bash

  [+] Applying manifests (0.0251 seconds) FINISHED
   => Verifying integrity of SecretsEngine 'kv'... done
   => Updating PasswordPolicy 'example'... done
   => Verifying integrity of Password 'kv/hello'... done
  Thanks for choosing Vault Autopilot!

Vault Autopilot will update the password policy on your Vault server to reflect the changes in the manifest file.

.. warning::

  Keep in mind that updating your password policy won't automatically update
  existing passwords. If you want to generate a new password that meets the
  updated policy, you'll need to bump the version of the Password resource. For
  example:

  .. code:: yaml

     kind: Password
     spec:
       path: hello
       secretsEnginePath: kv
       policyPath: example
       secretKey: foo
       # bump the version from 1 to 2 to trigger a new password generation
       version: 2

  That's it!


Conclusion
==========

Congratulations! You've successfully applied your first manifest using Vault
Autopilot CLI.
