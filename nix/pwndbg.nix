{
  pkgs ? import <nixpkgs> { }
  , python3 ? pkgs.python3
  , gdb ? pkgs.gdb
  , inputs ? null
}:
let
  binPath = pkgs.lib.makeBinPath ([
    python3.pkgs.pwntools   # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/wrappers/checksec.py#L8
  ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
    python3.pkgs.ropper     # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/ropper.py#L30
    python3.pkgs.ropgadget  # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/rop.py#L34
  ]);

  pyEnv = pkgs.poetry2nix.mkPoetryEnv {
    groups = [];  # put [ "dev" ] to build "dev" dependencies
    checkGroups = [];  # put [ "dev" ] to build "dev" dependencies
    projectDir = inputs.pwndbg;
    python = python3;
    overrides = pkgs.poetry2nix.overrides.withDefaults (self: super: {
      pip = python3.pkgs.pip;  # fix infinite loop in nix, look here: https://github.com/nix-community/poetry2nix/issues/1184#issuecomment-1644878841
      unicorn = python3.pkgs.unicorn;  # fix build for aarch64 (but it will use same version like in nixpkgs)

      # disable build from source, because rust's hash had to be repaired many times, see: PR https://github.com/pwndbg/pwndbg/pull/2024
      cryptography = super.cryptography.override {
        preferWheel = true;
      };

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
    });
  };

  pwndbgVersion = pkgs.lib.readFile (pkgs.runCommand "pwndbgVersion" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    mkdir pkg
    cd pkg
    cp ${inputs.pwndbg + "/pwndbg/lib/version.py"} version.py
    python3 -c 'import version; print(version.__version__, end="")' > $out
  '');

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

      ln -s ${pyEnv} $out/share/pwndbg/.venv

      makeWrapper ${gdb}/bin/gdb $out/bin/pwndbg \
        --add-flags "--quiet --early-init-eval-command=\"set charset UTF-8\" --early-init-eval-command=\"set auto-load safe-path /\" --command=$out/share/pwndbg/gdbinit.py" \
        --prefix PATH : ${binPath} \
        --set LC_CTYPE C.UTF-8
    '';

    meta = {
      python3 = python3;
      gdb = gdb;
    };
  };
in
  pwndbg
