{
  pkgs ? import <nixpkgs> { },
  python3 ? pkgs.python3,
  inputs ? null,
  isDev ? false,
  lib,
  ...
}:
pkgs.poetry2nix.mkPoetryEnv {
  groups = lib.optionals isDev [ "dev" ];
  checkGroups = lib.optionals isDev [ "dev" ];
  projectDir = inputs.pwndbg;
  python = python3;
  overrides = pkgs.poetry2nix.overrides.withDefaults (
    self: super: {
      pip = python3.pkgs.pip; # fix infinite loop in nix, look here: https://github.com/nix-community/poetry2nix/issues/1184#issuecomment-1644878841
      unicorn = python3.pkgs.unicorn; # fix build for aarch64 (but it will use same version like in nixpkgs)

      # disable build from source, because rust's hash had to be repaired many times, see: PR https://github.com/pwndbg/pwndbg/pull/2024
      cryptography = super.cryptography.override { preferWheel = true; };

      unix-ar = super.unix-ar.overridePythonAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ self.setuptools ];
      });

      pt = super.pt.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ super.poetry-core ];
      });
      capstone = super.capstone.overridePythonAttrs (old: {
        # fix darwin
        preBuild = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
          sed -i 's/^IS_APPLE := .*$/IS_APPLE := 1/' ./src/Makefile
        '';
        # fix build for aarch64: https://github.com/capstone-engine/capstone/issues/2102
        postPatch = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
          substituteInPlace setup.py --replace manylinux1 manylinux2014
        '';
      });
      sortedcontainers-stubs = super.sortedcontainers-stubs.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ super.poetry-core ];
      });

      # Dev-only dependencies

      # Because compiling mypy is slow
      mypy = super.mypy.override { preferWheel = true; };
      types-gdb = super.types-gdb.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
      });
      vermin = super.vermin.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
      });
      # Hash issues, so just wheel
      ruff = super.ruff.override { preferWheel = true; };
    }
  );
}
