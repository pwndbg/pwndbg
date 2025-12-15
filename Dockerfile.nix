# This dockerfile was created for development & testing purposes, for DNF-based distro.
#
# Build as:             docker build -f Dockerfile.nix -t pwndbg .
#
# For testing use:      docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwndbg bash
#
# For development, mount the directory so the host changes are reflected into container:
#   docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
#

ARG image=nixos/nix:latest
FROM $image

WORKDIR /pwndbg

ENV LANG=en_US.utf8
ENV TZ=America/New_York

COPY ./flake.nix /pwndbg/
COPY ./flake.lock /pwndbg/
COPY ./uv.lock /pwndbg/
COPY ./pyproject.toml /pwndbg/
COPY ./nix /pwndbg/nix

RUN touch README.md && mkdir pwndbg && touch pwndbg/empty.py
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

RUN nix develop --accept-flake-config --profile /nix-profile
RUN nix develop --accept-flake-config /nix-profile

COPY . /pwndbg/

ENTRYPOINT ["nix", "develop", "--accept-flake-config", "/nix-profile", "--command"]
