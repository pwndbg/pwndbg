#!/bin/sh

# This script performs a release build similar to what CI/CD does
# It just does everything at once :)
#
# It can be useful if one needs to build the release binaries manually

O="--extra-experimental-features nix-command --extra-experimental-features flakes"

nix build $O '.#pwndbg' -o result-pwndbg
nix build $O '.#rpm' -o dist-rpm
nix build $O '.#deb' -o dist-deb
nix build $O '.#apk' -o dist-apk
nix build $O '.#archlinux' -o dist-archlinux
nix build $O '.#tarball' -o dist-tarball
