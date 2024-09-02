# This should be kept in sync with setup-dev.sh and lint.sh requirements
{
  pkgs ?
    # If pkgs is not defined, instantiate nixpkgs from locked commit
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
  pyEnv = import ./pyenv.nix {
    inherit pkgs python3 inputs isLLDB;
    lib = pkgs.lib;
    isDev = true;
  };
in
{
  default = pkgs.mkShell {
    NIX_CONFIG = "extra-experimental-features = nix-command flakes repl-flake";
    # Anything not handled by the poetry env
    nativeBuildInputs = (with pkgs; [
      # from setup-dev.sh
      nasm
      gcc
      curl
      gdb
      parallel
      qemu
      netcat-openbsd
      zig_0_10 # matches setup-dev.sh
      go

      pyEnv
    ]) ++ pkgs.lib.optionals isLLDB (with pkgs; [
      lldb_19
    ]);
    shellHook = ''
      export PWNDBG_VENV_PATH="PWNDBG_PLEASE_SKIP_VENV"
      export ZIGPATH="${pkgs.lib.getBin pkgs.zig_0_10}/bin/"
    '';
  };
}
