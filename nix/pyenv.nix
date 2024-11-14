{
  pkgs ? import <nixpkgs> { },
  python3 ? pkgs.python3,
  inputs ? null,
  isDev ? false,
  isLLDB ? false,
  lib,
  ...
}:
pkgs.poetry2nix.mkPoetryEnv {
  groups = [ "main" ] ++ lib.optionals isDev [ "dev" ] ++ lib.optionals isLLDB [ "lldb" ];
  checkGroups = lib.optionals isDev [ "dev" ] ++ lib.optionals isLLDB [ "lldb" ];
  projectDir = inputs.pwndbg;
  python = python3;
  overrides = pkgs.poetry2nix.overrides.withDefaults (
    self: super: {
      pip = python3.pkgs.pip; # fix infinite loop in nix, look here: https://github.com/nix-community/poetry2nix/issues/1184#issuecomment-1644878841

      # disable build from source, because rust's hash had to be repaired many times, see: PR https://github.com/pwndbg/pwndbg/pull/2024
      cryptography = super.cryptography.override { preferWheel = true; };

      unix-ar = super.unix-ar.overridePythonAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ self.setuptools ];
      });

      pt = super.pt.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ super.poetry-core ];
      });

      # Patch psutil to work on macOS (Darwin)
      # https://github.com/pwndbg/pwndbg/pull/2526#issuecomment-2476732310
      psutil = (
        super.psutil.overridePythonAttrs (
          old:
          pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
            stdenv = pkgs.overrideSDK pkgs.stdenv "11.0";
            NIX_CFLAGS_COMPILE = "-DkIOMainPortDefault=0";
            buildInputs =
              old.buildInputs or [ ]
              ++ pkgs.lib.optionals pkgs.stdenv.isx86_64 [ pkgs.darwin.apple_sdk.frameworks.CoreFoundation ]
              ++ [ pkgs.darwin.apple_sdk.frameworks.IOKit ];
          }
        )
      );

      # Disable tests for unicorn on macOS in GitHub Actions (to avoid segmentation faults)
      # https://github.com/pwndbg/pwndbg/pull/2526#issuecomment-2476732310
      unicorn = python3.pkgs.unicorn.overridePythonAttrs (
        old:
        pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          doCheck = false;
        }
      );

      capstone =
        # capstone=5.0.3 build is broken only in darwin :(, soo we use wheel
        if pkgs.stdenv.isDarwin then
          super.capstone.override { preferWheel = true; }
        else
          super.capstone.overridePythonAttrs (old: {
            # fix darwin
            preBuild = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              sed -i 's/^IS_APPLE := .*$/IS_APPLE := 1/' ./src/Makefile
            '';
            # fix darwin
            nativeBuildInputs =
              (old.nativeBuildInputs or [ ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
                pkgs.cmake
                pkgs.fixDarwinDylibNames
              ];
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
