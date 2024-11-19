# Packages installed by this file should be kept in sync with setup-dev.sh and lint.sh requirements
{
  pkgs ? # If pkgs is not defined, instantiate nixpkgs from locked commit
    let
      lock = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked;
      nixpkgs = fetchTarball {
        url = "https://github.com/nixos/nixpkgs/archive/${lock.rev}.tar.gz";
        sha256 = lock.narHash;
      };
    in
    import nixpkgs { overlays = [ ]; },
  python3 ? pkgs.python3,
  inputs ? null,
  isLLDB ? false,
  ...
}:
let
  lib = pkgs.lib;
  pyEnv = import ./pyenv.nix {
    inherit
      pkgs
      lib
      python3
      inputs
      isLLDB
      ;
    isDev = true;
  };
  jemalloc-static = pkgs.jemalloc.overrideAttrs (
    finalAttrs: previousAttrs: {
      version = "5.3.0"; # version match setup-dev.sh
      src = pkgs.fetchurl {
        url = "https://github.com/jemalloc/jemalloc/releases/download/${finalAttrs.version}/${finalAttrs.pname}-${finalAttrs.version}.tar.bz2";
        sha256 = "sha256-LbgtHnEZ3z5xt2QCGbbf6EeJvAU3mDw7esT3GJrs/qo=";
      };
      configureFlags = (previousAttrs.configureFlags or [ ]) ++ [
        "--enable-static"
        "--disable-shared"
      ];
      # debug symbols currently required for jemalloc.py type resolution
      preBuild = ''
        makeFlagsArray+=(CFLAGS="-O0 -g")
      '';
      postInstall = ''
        ${previousAttrs.postInstall or ""}
        cp -v lib/libjemalloc.a $out/lib/
      '';
      dontStrip = true; # don't strip the debug symbols we added
    }
  );
in
{
  default = pkgs.mkShell {
    NIX_CONFIG = "extra-experimental-features = nix-command flakes repl-flake";
    # Anything not handled by the poetry env
    nativeBuildInputs =
      builtins.attrValues {
        inherit (pkgs)
          # from setup-dev.sh
          nasm
          gcc
          curl
          gdb
          parallel
          qemu
          netcat-openbsd
          zig_0_10 # version match setup-dev.sh
          go

          # for onegadget command
          one_gadget

          # from qemu-tests.sh
          binutils
          ;
      }
      ++ [
        jemalloc-static
        # from qemu-tests.sh
        (pkgs.writeShellScriptBin "gdb-multiarch" ''
          exec ${lib.getBin pkgs.gdb}/bin/gdb "$@"
        '')
        pkgs.pkgsCross.aarch64-multiplatform.buildPackages.binutils
        pkgs.pkgsCross.riscv64.buildPackages.binutils
        pkgs.pkgsCross.mipsel-linux-gnu.buildPackages.binutils
        (pkgs.writeShellScriptBin "aarch64-linux-gnu-gcc" ''
          exec ${lib.getBin pkgs.pkgsCross.aarch64-multiplatform.buildPackages.gcc}/bin/aarch64-unknown-linux-gnu-gcc "$@"
        '')
        (pkgs.writeShellScriptBin "riscv64-linux-gnu-gcc" ''
          exec ${lib.getBin pkgs.pkgsCross.riscv64.buildPackages.gcc}/bin/riscv64-unknown-linux-gnu-gcc "$@"
        '')

        pyEnv
      ]
      ++ pkgs.lib.optionals isLLDB [
        pkgs.lldb_19
      ];
    shellHook = ''
      export PWNDBG_VENV_PATH="PWNDBG_PLEASE_SKIP_VENV"
      export ZIGPATH="${pkgs.lib.getBin pkgs.zig_0_10}/bin/"
    '';
  };
}
