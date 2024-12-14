{
  pkgs,
}:
paths:
# Original file copied from https://github.com/3noch/nix-bundle-exe
# But it was modified/patched for pwndbg usecase!
# May be:
#  1) a derivation,
#  2) a path to a directory containing bin/, or
#  3) a path to an executable.
let
  deps =
    if pkgs.stdenv.isDarwin then
      [
        pkgs.darwin.cctools
        pkgs.darwin.binutils
        pkgs.darwin.sigtool
      ]
    else if pkgs.stdenv.isLinux then
      [
        pkgs.patchelf
      ]
    else
      throw "Unsupported platform: only darwin and linux are supported";
in
pkgs.runCommand "pwndbg-bundler"
  {
    nativeBuildInputs = deps ++ [
      pkgs.nukeReferences
      pkgs.python3
    ];
  }
  ''
    set -euo pipefail
    python3 ${./bundle.py} "$out" ${pkgs.lib.escapeShellArgs paths}
    find $out -empty -type d -delete
  ''
