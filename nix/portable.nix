{
  pkgs ? import <nixpkgs> { },
  pwndbg ? import ./pwndbg.nix { },
}:
let
  gdb = pwndbg.meta.gdb;
  python3 = pwndbg.meta.python3;
  pwndbgVenv = pwndbg.meta.pwndbgVenv;

  gdbBundledLib = pkgs.callPackage ./bundle { } "${gdb}/bin/gdb";
  pyEnvBundledLib = pkgs.callPackage ./bundle { } "${pwndbgVenv}/lib/";

  ldName = pkgs.lib.readFile (
    pkgs.runCommand "bundle" { nativeBuildInputs = [ pkgs.patchelf ]; } ''
      echo -n $(patchelf --print-interpreter "${gdbBundledLib}/exe/gdb") > $out
    ''
  );

  pwndbgBundleBin = pkgs.writeScript "pwndbg" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    export PYTHONHOME="$dir"
    exec "$dir/lib/${ldName}" "$dir/exe/gdb" --quiet --early-init-eval-command="set auto-load safe-path /" --command=$dir/exe/gdbinit.py "$@"
  '';

  portable =
    pkgs.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.name;
          version = pwndbg.version;
          architecture = gdb.stdenv.targetPlatform.system;
        };
        nativeBuildInputs = [ pkgs.makeWrapper pkgs.proot ];
      }
      ''
        mkdir -p $out/pwndbg/bin/
        mkdir -p $out/pwndbg/lib/
        mkdir -p $out/pwndbg/exe/
        mkdir -p $out/pwndbg/share/gdb/
        touch $out/pwndbg/exe/.skip-venv

        cp -rf ${gdbBundledLib}/exe/* $out/pwndbg/exe/
        cp -rf ${gdbBundledLib}/lib/* $out/pwndbg/lib/
        cp -rf ${pyEnvBundledLib}/lib/* $out/pwndbg/lib/

        cp -rf ${pwndbgVenv}/share/gdb/* $out/pwndbg/share/gdb/
        cp -rf ${gdb}/share/gdb/* $out/pwndbg/share/gdb/
        chmod -R +w $out

        cp -rf ${pwndbg.src}/pwndbg $out/pwndbg/lib/${python3.libPrefix}/site-packages/
        cp ${pwndbg.src}/gdbinit.py $out/pwndbg/exe/

        cp ${pwndbgBundleBin} $out/pwndbg/bin/pwndbg

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        substituteInPlace $out/pwndbg/lib/${python3.libPrefix}/subprocess.py --replace "'${pkgs.bash}/bin/sh'" "'/bin/sh'"

        # build pycache
        chmod -R +w $out/pwndbg/lib/${python3.libPrefix}/site-packages/pwndbg
        SOURCE_DATE_EPOCH=0 proot -b $out/pwndbg:/usr/lib/pwndbg ${pwndbgVenv}/bin/python3 -c "import compileall; compileall.compile_dir('/usr/lib/pwndbg/', force=True);"
      '';
in
portable
