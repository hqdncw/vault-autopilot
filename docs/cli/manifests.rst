#########
Manifests
#########

At the heart of Vault Autopilot is the manifest file, a declarative
configuration file that defines the desired state of your Vault infrastructure.
Manifests provide a clear and concise way to specify the resources you want to
create, update, or delete in Vault, including secrets, policies, and secrets
engines. By using manifests, you can version control your Vault configuration,
track changes, and collaborate with team members. Vault Autopilot then uses
these manifests to automatically apply the required changes to your Vault
infrastructure, ensuring that your desired state is consistently maintained.

Available resources
===================

Vault Autopilot supports a range of resources that can be defined in manifest files, allowing you to manage your Vault infrastructure with ease.


Secrets Engines
---------------

A Secrets Engine provides declarative updates for `Secrets Engine <https://developer.hashicorp.com/vault/docs/secrets>`_ in Vault.


Creating a Secrets Engine
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: SecretsEngine
   spec:
     path: kv
     engine:
       type: kv-v2

In this example, we're defining a Secrets Engine with a path of ``kv`` and
specifying the ``kv-v2`` engine type.


Available keys
~~~~~~~~~~~~~~

.. warning::

   Currently, only secrets engines of type ``kv-v2`` or ``pki`` are supported.
   Support for other engine types may be added in future releases.

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/secrets_engine.json
      :literal:


Issuers
-------

An Issuer is responsible for providing declarative updates to the Vault PKI
Certificate Authority. Using the vault-autopilot CLI, you can manage both `root
<https://developer.hashicorp.com/vault/docs/secrets/pki/quick-start-root-ca>`_
and `intermediate
<https://developer.hashicorp.com/vault/docs/secrets/pki/quick-start-intermediate-ca>`_
issuers.

By default, any Issuer resource that doesn't have a
``chaining`` field is treated as a root Issuer. In other words, if you don't
specify a ``chaining`` field, the system assumes you're creating a root Issuer.


Creating a root Issuer
~~~~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: Issuer
   spec:
     name: root-2024
     secretsEnginePath: pki
     certificate:
       type: internal
       commonName: "example.com Root Authority"
       ttl: "87600h"


Creating an intermediate Issuer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: Issuer
   spec:
     name: intmd-2024
     secretsEnginePath: pki_int
     certificate:
       type: internal
       commonName: "example.com Intermediate Authority"
       ttl: "43800h"
     chaining:
       upstreamIssuerRef: "pki/root-2024"

The ``upstreamIssuerRef`` field is a reference to the parent Issuer that signed
the current Issuer's certificate, pointing to the Issuer's mount point and
name, like ``pki/root-2024``, which says 'find the Issuer named ``root-2024``
in the ``pki`` secrets engine'.


Available keys
~~~~~~~~~~~~~~

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/issuer.json
      :literal:


PKI Roles
---------

A PKI Role provides declarative updates for `PKI roles
<https://developer.hashicorp.com/vault/tutorials/secrets-management/pki-engine#step-3-create-a-role>`_
in Vault.

Creating a PKI Role
~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: PKIRole
   spec:
     name: example
     secretsEnginePath: pki
     role:
       issuerRef: root-2024
       allowedDomains: "example.com"
       allowSubdomains: true
       maxTtl: "720h"

This example creates a PKI Role in Vault with the following configuration:

- The role uses the ``root-2024`` issuer reference.
- Certificates can only be issued for the "example.com" domain, and subdomains
  are also allowed.
- The maximum time to live (TTL) for certificates issued by this role is 30
  days (720 hours).

Available keys
~~~~~~~~~~~~~~

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/pki_role.json
      :literal:


SSH Keys
--------

An SSH Key provides declarative updates for secrets in Vault.


Creating an SSH Key
~~~~~~~~~~~~~~~~~~~

Here's an example of how to create an SSH Key:

.. code:: yaml

   kind: SSHKey
   spec:
     secretsEnginePath: kv
     path: id_rsa
     keyOptions:
       type: rsa
       bits: 4096
     privateKey:
       secretKey: private_key
     publicKey:
       secretKey: public_key
     version: 1

In this example, we're creating an SSH Key with the following properties:

- The path for the secret (SSH Key) is specified as ``id_rsa``.
- The ``keyOptions`` section defines the type and size of the key, in this
  case, an RSA key with 4096 bits.
- The ``privateKey`` and ``publicKey`` sections specify the secret keys where
  the private and public keys will be stored, respectively.
- The version is set to 1, indicating the version of the SSH Key. You can bump
  this version number when you want to regenerate the SSH key pair, allowing
  you to easily manage and rotate your SSH keys.

Available keys
~~~~~~~~~~~~~~

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/ssh_key.json
      :literal:


Password Policies
-----------------

A Password Policy provides declarative updates for `Password Policies
<https://developer.hashicorp.com/vault/docs/concepts/password-policies>`_ in
Vault.

Creating a Password Policy
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: PasswordPolicy
   spec:
     path: example
     policy:
       length: 128
       rules:
         - charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            minChars: 1
         - charset: "0123456789"
            minChars: 1
         - charset: "!@#$%^&*"
            minChars: 1

In this example, we're creating a Password Policy with the following properties:

- The length is set to 128, which specifies the minimum length of the password.
- The rules section defines a list of character set rules that must be met for
  a password to be valid.

  1. The first rule requires at least one uppercase letter
     (``ABCDEFGHIJKLMNOPQRSTUVWXYZ``).
  2. The second rule requires at least one digit (``0123456789``).
  3. The third rule requires at least one special character (``!@#$%^&*``).


Available keys
~~~~~~~~~~~~~~

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/password.json
      :literal:

Password
--------

A Password provides declarative updates for secrets in Vault.

Creating a Password
~~~~~~~~~~~~~~~~~~~

.. code:: yaml

   kind: Password
   spec:
     path: my-secret
     secretsEnginePath: kv
     policyPath: example
     secretKey: foo
     version: 1

.. warning::

  Keep in mind that updating your password policy won't automatically update
  existing passwords. If you want to generate a new password that meets the
  updated policy, you'll need to bump the version of the Password resource. For
  example:

  .. code:: yaml

     kind: Password
     spec:
       path: my-secret
       secretsEnginePath: kv
       policyPath: example
       secretKey: foo
       # bump the version from 1 to 2 to trigger a new password generation
       version: 2

  That's it!

Available keys
~~~~~~~~~~~~~~

.. container:: toggle, toggle-hidden

   .. include:: ../_static/schemas/password.json
      :literal:
