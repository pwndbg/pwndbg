#!/bin/sh
nix --extra-experimental-features nix-command --extra-experimental-features flakes flake update poetry2nix
