{
  pkgs ? import <nixpkgs> { },
  pwndbg ? import ./pwndbg.nix { },
}:
let
  gdb = pwndbg.meta.gdb;
  python3 = pwndbg.meta.python3;

  gdbBundledLib = pkgs.callPackage ./bundle { } "${gdb}/bin/gdb";
  pyEnvBundledLib = pkgs.callPackage ./bundle { } "${pwndbg}/share/pwndbg/.venv/lib/";

  ldName = pkgs.lib.readFile (
    pkgs.runCommand "bundle" { nativeBuildInputs = [ pkgs.patchelf ]; } ''
      echo -n $(patchelf --print-interpreter "${gdbBundledLib}/exe/gdb") > $out
    ''
  );

  pwndbgBundleBin = pkgs.writeScript "pwndbg" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    export PYTHONHOME="$dir"
    export PYTHONPYCACHEPREFIX="$dir/cache/"
    export PWNDBG_PENV_PATH="PWNDBG_PLEASE_SKIP_VENV"
    exec "$dir/lib/${ldName}" "$dir/exe/gdb" --quiet --early-init-eval-command="set charset UTF-8" --early-init-eval-command="set auto-load safe-path /" --command=$dir/exe/gdbinit.py "$@"
  '';
  # for cache: pwndbg --eval-command="py import compileall; compileall.compile_dir('/usr/lib/pwndbg/'); exit()"

  portable =
    pkgs.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.name;
          version = pwndbg.version;
          architecture = gdb.stdenv.targetPlatform.system;
        };
        nativeBuildInputs = [ pkgs.makeWrapper ];
      }
      ''
        mkdir -p $out/pwndbg/bin/
        mkdir -p $out/pwndbg/lib/
        mkdir -p $out/pwndbg/exe/
        mkdir -p $out/pwndbg/share/gdb/
        mkdir -p $out/pwndbg/cache/

        cp -rf ${gdbBundledLib}/exe/* $out/pwndbg/exe/
        cp -rf ${gdbBundledLib}/lib/* $out/pwndbg/lib/
        cp -rf ${pyEnvBundledLib}/lib/* $out/pwndbg/lib/

        cp -rf ${pwndbg}/share/pwndbg/.venv/share/gdb/* $out/pwndbg/share/gdb/
        cp -rf ${gdb}/share/gdb/* $out/pwndbg/share/gdb/
        chmod -R +w $out

        cp -rf ${pwndbg.src}/pwndbg $out/pwndbg/lib/${python3.libPrefix}/site-packages/
        cp ${pwndbg.src}/gdbinit.py $out/pwndbg/exe/

        cp ${pwndbgBundleBin} $out/pwndbg/bin/pwndbg

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        substituteInPlace $out/pwndbg/lib/${python3.libPrefix}/subprocess.py --replace "'${pkgs.bash}/bin/sh'" "'/bin/sh'"
      '';
in
portable
