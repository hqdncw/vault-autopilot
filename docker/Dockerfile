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
ENV PIP_CACHE_DIR=$PIP_CACHE_DIR

RUN --mount=type=cache,target=$PIP_CACHE_DIR,sharing=locked \
  mkdir -p $PIP_CACHE_DIR && \
  pip install .[cli]

COPY ./src/ ./src/
COPY ./README.md ./README.md

FROM gcr.io/distroless/python3-debian12@sha256:e8e50bc861b16d916f598d7ec920a8cef1e35e99b668a738fe80c032801ceb78 AS runtime

ARG VENV_DIR="/opt/venv"
COPY --from=build $VENV_DIR $VENV_DIR
ENV PATH="$VENV_DIR/bin:$PATH"

ARG DIST_DIR="/usr/local/src"
COPY --from=build --chmod=400 $DIST_DIR $DIST_DIR

WORKDIR /srv/vault-autopilot

ENV PYTHONPATH="$DIST_DIR/vault-autopilot/src/:$VENV_DIR/lib/python3.11/site-packages:$PYTHONPATH"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED=1

RUN [ "python3", "-m", "compileall", "$DIST_DIR", "/usr/lib/python3.11" ]

ENTRYPOINT ["python", "-m", "vault_autopilot"]
