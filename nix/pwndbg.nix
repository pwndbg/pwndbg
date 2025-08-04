{
  pkgs,
  inputs,
  python3 ? pkgs.python3,
  gdb ? pkgs.pwndbg_gdb,
  lldb ? pkgs.pwndbg_lldb,
  isDev ? false,
  isLLDB ? false,
  ...
}:
let
  lib = pkgs.lib;
  extraPackags = [
    python3.pkgs.pwntools # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/wrappers/checksec.py#L8
  ]
  ++ lib.optionals pkgs.stdenv.isLinux [
    python3.pkgs.ropper # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/ropper.py#L30
  ];

  pyEnv = import ./pyenv.nix {
    inherit
      pkgs
      inputs
      python3
      isDev
      isLLDB
      ;
  };

  pwndbgVersion =
    let
      versionFile = builtins.readFile "${inputs.self}/pwndbg/lib/version.py";
      versionMatch = builtins.match ".*\n__version__ = \"([0-9]+.[0-9]+.[0-9]+)\".*" versionFile;
      version = if versionMatch == null then "unknown" else (builtins.elemAt versionMatch 0);
    in
    version;

  pwndbg_gdb =
    pkgs.runCommand "pwndbg"
      {
        version = pwndbgVersion;
        nativeBuildInputs = [ pkgs.pkgsBuildHost.makeWrapper ];
      }
      ''
        mkdir -p $out/bin/
        makeWrapper ${pyEnv}/bin/pwndbg $out/bin/pwndbg \
            --prefix PATH : ${lib.makeBinPath ([ gdb ] ++ extraPackags)}
      '';

  pwndbg_lldb =
    pkgs.runCommand "pwndbg-lldb"
      {
        version = pwndbgVersion;
        nativeBuildInputs = [ pkgs.pkgsBuildHost.makeWrapper ];
      }
      ''
        mkdir -p $out/bin/
        makeWrapper ${pyEnv}/bin/pwndbg-lldb $out/bin/pwndbg-lldb \
            --prefix PATH : ${lib.makeBinPath ([ lldb ] ++ extraPackags)}
      '';

  pwndbg_final = (if isLLDB then pwndbg_lldb else pwndbg_gdb) // {
    meta = {
      pwndbgVenv = pyEnv;
      python3 = python3;
      gdb = gdb;
      lldb = lldb;
      isLLDB = isLLDB;
    };
  };
in
pwndbg_final
