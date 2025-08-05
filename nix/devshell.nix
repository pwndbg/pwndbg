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
    isEditable = true;
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
    NIX_CONFIG = "extra-experimental-features = nix-command flakes";
    # Anything not handled by the poetry env
    nativeBuildInputs =
      builtins.attrValues {
        inherit (pkgs)
          # from setup-dev.sh
          nasm
          gcc
          curl
          parallel
          qemu
          go

          # for onegadget command
          one_gadget

          # from qemu-tests.sh
          binutils
          ;
      }
      ++ [
        jemalloc-static
        pkgs.gdb
        pyEnv
      ]
      ++ pkgs.lib.optionals isLLDB [
        pkgs.lldb_20
      ];
    shellHook = ''
      export PWNDBG_NO_AUTOUPDATE=1
      export PWNDBG_NO_UV=1
      export PWNDBG_VENV_PATH="${pyEnv}"
      export REPO_ROOT=$(git rev-parse --show-toplevel)
    '';
  };
}
