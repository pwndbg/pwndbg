# This dockerfile was created for development & testing purposes, for APT-based distro.
#
# Build as:             docker build -t pwndbg .
#
# For testing use:      docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwndbg bash
#
# For development, mount the directory so the host changes are reflected into container:
#   docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
#

ARG image=mcr.microsoft.com/devcontainers/base:jammy
FROM $image AS base

WORKDIR /pwndbg

ENV PIP_NO_CACHE_DIR=true
ENV LANG=en_US.utf8
ENV TZ=America/New_York
ENV ZIGPATH=/opt/zig
ENV PWNDBG_VENV_PATH=/venv
ENV UV_PROJECT_ENVIRONMENT=/venv

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y locales && \
    rm -rf /var/lib/apt/lists/* && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    apt-get update && \
    apt-get install -y vim

ADD ./setup.sh /pwndbg/
ADD ./uv.lock /pwndbg/
ADD ./pyproject.toml /pwndbg/

# pyproject.toml requires these files, pip install would fail
RUN touch README.md && mkdir pwndbg && touch pwndbg/empty.py

RUN DEBIAN_FRONTEND=noninteractive ./setup.sh

# Comment these lines if you won't run the tests.
ADD ./setup-dev.sh /pwndbg/
RUN ./setup-dev.sh

# Cleanup dummy files
RUN rm README.md && rm -rf pwndbg

FROM base AS full

ADD . /pwndbg/

ARG LOW_PRIVILEGE_USER="vscode"

ENV PATH="${PWNDBG_VENV_PATH}/bin:${PATH}"

# Add .gdbinit to the home folder of both root and vscode users (if vscode user exists)
# This is useful for a VSCode dev container, not really for test builds
RUN if [ ! -f ~/.gdbinit ]; then echo "source /pwndbg/gdbinit.py" >> ~/.gdbinit; fi && \
    if id -u ${LOW_PRIVILEGE_USER} > /dev/null 2>&1; then \
        su ${LOW_PRIVILEGE_USER} -c 'if [ ! -f ~/.gdbinit ]; then echo "source /pwndbg/gdbinit.py" >> ~/.gdbinit; fi'; \
    fi
