# This dockerfile was created for development & testing purposes, for APT-based distros.
# images available:
#   ubuntu24.04 | ubuntu22.04 | debian12
#
# Run using prebuilt image (pulls image and bind-mounts working dir into /pwndbg):
#   docker compose run --rm -v $(pwd):/pwndbg ubuntu24.04
#
# Update your prebuilt image:
#   docker compose pull ubuntu24.04

ARG image=mcr.microsoft.com/devcontainers/base:jammy
FROM $image AS base

WORKDIR /pwndbg

ENV LANG=en_US.utf8
ENV TZ=America/New_York
ENV PWNDBG_VENV_PATH=/venv
ENV UV_PROJECT_ENVIRONMENT=/venv

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        locales vim ccache && \
    localedef -i en_US -c -f UTF-8 en_US.UTF-8

# setup.sh needs scripts/common.sh
COPY ./scripts/common.sh /pwndbg/scripts/

COPY ./uv.lock /pwndbg/
COPY ./pyproject.toml /pwndbg/

# pyproject.toml requires these files, pip install would fail
RUN touch README.md && mkdir pwndbg && touch pwndbg/empty.py

COPY ./setup.sh /pwndbg/
RUN DEBIAN_FRONTEND=noninteractive ./setup.sh

# Comment these lines if you won't run the tests.
COPY ./setup-dev.sh /pwndbg/
RUN --mount=type=cache,id=ccache,target=/root/.ccache,sharing=locked \
    CCACHE_DIR=/root/.ccache \
    CC="ccache gcc" \
    ./setup-dev.sh

# Cleanup dummy files
RUN rm README.md && rm -rf pwndbg

FROM base AS full

COPY . /pwndbg/

ENV PATH="${PWNDBG_VENV_PATH}/bin:${PATH}"
