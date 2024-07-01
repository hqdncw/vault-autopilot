# Vault-Autopilot CLI


## Description

Vault-Autopilot CLI is a Python-based command-line interface for automating
HashiCorp Vault tasks.

## How to use this image

To get started with the Vault-Autopilot CLI, simply run the Docker image with
the ``--help`` flag to see the available commands and options.

```bash
docker run --rm hqdncw/vault-autopilot:latest --help
```

For a more comprehensive guide to getting started with the Vault-Autopilot CLI,
please refer to our [Getting Started
Guide](https://hqdncw.github.io/vault-autopilot/cli/getting_started.html). This
guide provides a step-by-step introduction to using the Vault-Autopilot CLI,
including configuration, authentication, and common use cases


## Environment Variables

For a complete list of available environment variables, please refer to the
[Configuration Documentation](https://hqdncw.github.io/vault-autopilot/cli/configuration.html#environment-variables).

To set environment variables, simply pass them to the container when running
it. For example:

```bash
docker run --rm -e BASEURL="" -e AUTH__TOKEN="" hqdncw/vault-autopilot:latest --help
```


## Learn More

Visit the [Vault-Autopilot CLI GitHub
repository](https://github.com/hqdncw/vault-autopilot) for more information.
