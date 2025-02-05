#!/bin/sh
nix --extra-experimental-features "nix-command flakes" build .#pwndbg
