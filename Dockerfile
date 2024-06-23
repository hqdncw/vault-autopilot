# syntax=docker/dockerfile:1.5-labs

ARG PYTHON_VERSION="3.11.2-slim"

FROM python:$PYTHON_VERSION AS build

RUN --mount=type=cache,target=/var/cache/apt \
  rm -f /etc/apt/apt.conf.d/docker-clean && \
	apt-get update && \
	apt-get install -yqq --no-install-recommends \
  gcc && \
  rm -rf /var/lib/apt/lists/*

# Enable venv
ARG VENV_DIR="/opt/venv"
RUN python3 -m venv $VENV_DIR
ENV PATH="$VENV_DIR/bin:$PATH"

ARG DIST_DIR="/usr/local/src/"
WORKDIR $DIST_DIR/vault-autopilot

COPY ./pyproject.toml .

# prepare pip for buildkit cache
ARG PIP_CACHE_DIR=/var/cache/buildkit/pip
ENV PIP_CACHE_DIR ${PIP_CACHE_DIR}
RUN mkdir -p $PIP_CACHE_DIR

RUN --mount=type=cache,target=$PIP_CACHE_DIR,sharing=locked \
  pip install .[cli]

COPY ./src/ ./src/
COPY ./README.md ./README.md

FROM gcr.io/distroless/python3-debian12:latest AS runtime

LABEL org.opencontainers.image.authors="hqdncw@gmail.com"
LABEL org.opencontainers.image.source="https://github.com/hqdncw/vault-autopilot"
LABEL org.opencontainers.image.description="Vault-Autopilot CLI"

ARG VENV_DIR="/opt/venv"
COPY --from=build $VENV_DIR $VENV_DIR
ENV PATH="$VENV_DIR/bin:$PATH"

ARG DIST_DIR="/usr/local/src"
COPY --from=build --chmod=444 $DIST_DIR $DIST_DIR

WORKDIR /srv/vault-autopilot

ENV PYTHONPATH="$DIST_DIR/vault-autopilot/src/:$VENV_DIR/lib/python3.11/site-packages:$PYTHONPATH"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONOPTIMIZE 1

ENTRYPOINT ["/usr/bin/python3.11", "-m", "vault_autopilot"]
