{
  pkgs,
  inputs,
  python3 ? pkgs.python3,
  isDev ? false,
  groups,
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
      groups
      isDev
      ;
  };

  pwndbgVersion =
    let
      versionFile = builtins.readFile "${inputs.self}/pwndbg/lib/version.py";
      versionMatch = builtins.match ".*\n__version__ = \"([0-9]+.[0-9]+.[0-9]+)\".*" versionFile;
      version = if versionMatch == null then "unknown" else (builtins.elemAt versionMatch 0);
    in
    version;

  mainProgram =
    if groups == [ "lldb" ] then
      "pwndbg-lldb"
    else if groups == [ "gdb" ] then
      "pwndbg"
    else
      "pwndbg-any";

  pwndbg_any =
    pkgs.runCommand mainProgram
      {
        version = pwndbgVersion;
        nativeBuildInputs = [ pkgs.pkgsBuildHost.makeWrapper ];
        meta = {
          pwndbgVenv = pyEnv;
          isLLDB = groups == [ "lldb" ];
          mainProgram = mainProgram;
        };
      }
      ''
        mkdir -p $out/bin/

        if [ -e "${pyEnv}/bin/gdb" ]; then
          makeWrapper ${pyEnv}/bin/pwndbg $out/bin/pwndbg \
            --prefix PATH : ${lib.makeBinPath extraPackags}
        fi

        if [ -e "${pyEnv}/bin/lldb" ]; then
          makeWrapper ${pyEnv}/bin/pwndbg-lldb $out/bin/pwndbg-lldb \
            --prefix PATH : ${lib.makeBinPath extraPackags}
        fi
      '';
in
pwndbg_any
