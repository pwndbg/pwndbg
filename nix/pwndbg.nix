{
  pkgs ? import <nixpkgs> { },
  python3 ? pkgs.python3,
  gdb ? pkgs.gdb,
  inputs ? null,
  isDev ? false,
}:
let
  binPath = pkgs.lib.makeBinPath (
    [
      python3.pkgs.pwntools # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/wrappers/checksec.py#L8
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
      python3.pkgs.ropper # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/ropper.py#L30
      python3.pkgs.ropgadget # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/rop.py#L34
    ]
  );

  pyEnv = import ./pyenv.nix {
    inherit
      pkgs
      python3
      inputs
      isDev
      ;
    lib = pkgs.lib;
  };

  pwndbgVersion = pkgs.lib.readFile (
    pkgs.runCommand "pwndbgVersion" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      mkdir pkg
      cd pkg
      cp ${inputs.pwndbg + "/pwndbg/lib/version.py"} version.py
      python3 -c 'import version; print(version.__version__, end="")' > $out
    ''
  );

  pwndbg = pkgs.stdenv.mkDerivation {
    name = "pwndbg";
    version = pwndbgVersion;

    src = pkgs.lib.sourceByRegex inputs.pwndbg [
      "pwndbg"
      "pwndbg/.*"
      "gdbinit.py"
    ];

    nativeBuildInputs = [ pkgs.makeWrapper ];

    installPhase = ''
      mkdir -p $out/share/pwndbg

      cp -r gdbinit.py pwndbg $out/share/pwndbg
      # Build self-contained init script for lazy loading from vanilla gdb
      # I purposely use insert() so I can re-import during development without having to restart gdb
      sed "2 i import sys, os\n\
      sys.path.insert(0, '${pyEnv}/${pyEnv.sitePackages}')\n\
      sys.path.insert(0, '$out/share/pwndbg/')\n\
      os.environ['PATH'] += ':${binPath}'\n" -i $out/share/pwndbg/gdbinit.py

      touch $out/share/pwndbg/.skip-venv
      makeWrapper ${gdb}/bin/gdb $out/bin/pwndbg \
        --add-flags "--quiet --early-init-eval-command=\"set auto-load safe-path /\" --command=$out/share/pwndbg/gdbinit.py"
    '';

    meta = {
      pwndbgVenv = pyEnv;
      python3 = python3;
      gdb = gdb;
    };
  };
in
pwndbg
