{
  pkgs,
  pwndbg,
  ...
}:
let
  pkgsNative = pkgs.pkgsBuildHost;
  lib = pkgs.lib;

  isLLDB = pwndbg.meta.isLLDB;
  lldb = pwndbg.meta.lldb;
  gdb = pwndbg.meta.gdb;
  python3 = pwndbg.meta.python3;
  pwndbgVenv = pwndbg.meta.pwndbgVenv;

  bundler = arg: (pkgsNative.callPackage ./bundle { } arg);

  ldName = lib.readFile (
    pkgsNative.runCommand "pwndbg-bundle-ld-name-IFD" { nativeBuildInputs = [ pkgsNative.patchelf ]; }
      ''
        echo -n $(basename $(patchelf --print-interpreter "${python3}/bin/python3")) > $out
      ''
  );
  ldLoader = if pkgs.stdenv.isLinux then "\"$dir/lib/${ldName}\"" else "";

  commonEnvs =
    lib.optionalString (pkgs.stdenv.isLinux && isLLDB) ''
      export LLDB_DEBUGSERVER_PATH="$dir/bin/lldb-server"
    ''
    + lib.optionalString pkgs.stdenv.isLinux ''
      export TERMINFO_DIRS=${
        lib.concatStringsSep ":" [
          # Fix issue Linux https://github.com/pwndbg/pwndbg/issues/2531
          "/etc/terminfo" # Debian, Fedora, Gentoo
          "/lib/terminfo" # Debian
          "/usr/share/terminfo" # upstream default, probably all FHS-based distros
          "/run/current-system/sw/share/terminfo" # NixOS
          "$dir/share/terminfo"
        ]
      }
    ''
    + lib.optionalString pkgs.stdenv.isDarwin ''
      export TERMINFO_DIRS=${
        lib.concatStringsSep ":" [
          # Fix issue Darwin https://github.com/pwndbg/pwndbg/issues/2531
          "/usr/share/terminfo" # upstream default, probably all FHS-based distros
          "$dir/share/terminfo"
        ]
      }
    ''
    + ''
      export PYTHONNOUSERSITE=1
      export PYTHONHOME="$dir"
      export PYTHONPATH=""
      export PATH="$dir/bin/:$PATH"
    '';

  wrapperBinPwndbgGdbinit = pkgs.writeScript "pwndbg-wrapper-bin-gdbinit" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    ${commonEnvs}
    exec ${ldLoader} "$dir/exe/gdb" --quiet --early-init-eval-command="set auto-load safe-path /" --command=$dir/exe/gdbinit.py "$@"
  '';
  wrapperBinPy =
    file:
    pkgs.writeScript "pwndbg-wrapper-bin-py" ''
      #!/bin/sh
      dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
      ${commonEnvs}
      exec ${ldLoader} "$dir/exe/python3" "$dir/${file}" "$@"
    '';
  wrapperBin =
    file:
    pkgs.writeScript "pwndbg-wrapper-bin" ''
      #!/bin/sh
      dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
      ${commonEnvs}
      exec ${ldLoader} "$dir/${file}" "$@"
    '';
  skipVenv = pkgs.writeScript "pwndbg-skip-venv" "";

  pwndbgGdbBundled = bundler (
    (lib.optionals (pkgs.libffi_portable != null) [
      "${lib.getLib pkgs.libffi_portable}/lib/"
      "lib/"
    ])
    ++
      # Darwin don't have gdbserver
      (lib.optionals (!pkgs.stdenv.isDarwin) [
        "${lib.getBin gdb}/bin/gdbserver"
        "exe/gdbserver"

        "${wrapperBin "exe/gdbserver"}"
        "bin/gdbserver"
      ])
    ++ [
      "${lib.getBin gdb}/bin/gdb"
      "exe/gdb"

      "${gdb}/share/gdb/"
      "share/gdb/"

      "${pwndbgVenv}/lib/"
      "lib/"

      "${python3}/lib/"
      "lib/"

      "${pwndbg.src}/pwndbg/"
      "lib/${python3.libPrefix}/site-packages/pwndbg/"

      "${pwndbg.src}/gdbinit.py"
      "exe/gdbinit.py"

      "${skipVenv}"
      "exe/.skip-venv"

      "${wrapperBinPwndbgGdbinit}"
      "bin/pwndbg"
    ]
  );

  pwndbgLldbBundled = bundler (
    (lib.optionals (pkgs.libffi_portable != null) [
      "${lib.getLib pkgs.libffi_portable}/lib/"
      "lib/"
    ])
    ++ [
      "${lib.getBin lldb}/bin/.lldb-wrapped"
      "exe/lldb"

      "${lib.getBin lldb}/bin/lldb-server"
      "exe/lldb-server"

      "${lib.getLib lldb}/lib/"
      "lib/"

      "${pwndbgVenv}/lib/"
      "lib/"

      "${python3}/lib/"
      "lib/"

      "${python3}/bin/python3"
      "exe/python3"

      "${pwndbg.src}/pwndbg/"
      "lib/${python3.libPrefix}/site-packages/pwndbg/"

      "${pwndbg.src}/lldbinit.py"
      "exe/lldbinit.py"

      "${pwndbg.src}/pwndbg-lldb.py"
      "exe/pwndbg-lldb.py"

      "${skipVenv}"
      "exe/.skip-venv"

      "${wrapperBin "exe/lldb-server"}"
      "bin/lldb-server"

      "${wrapperBin "exe/lldb"}"
      "bin/lldb"

      "${wrapperBinPy "exe/pwndbg-lldb.py"}"
      "bin/pwndbg-lldb"
    ]
  );
  pwndbgBundled = if isLLDB then pwndbgLldbBundled else pwndbgGdbBundled;

  portable =
    pkgsNative.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.meta.name;
          version = pwndbg.version;
          architecture =
            if isLLDB then lldb.stdenv.targetPlatform.system else gdb.stdenv.targetPlatform.system;
        };
      }
      ''
        mkdir -p $out/pwndbg/
        # copy
        cp -rf ${pwndbgBundled}/* $out/pwndbg/

        # writable out
        chmod -R +w $out

        # copy extra files
        cp -rf ${lib.getLib pkgs.ncurses}/share/terminfo/ $out/pwndbg/share/

        # fix ipython autocomplete
        cp -rf ${pwndbgVenv}/lib/${python3.libPrefix}/site-packages/parso/python/*.txt $out/pwndbg/lib/${python3.libPrefix}/site-packages/parso/python/

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        sed -i 's@/nix/store/.*/bin/sh@/bin/sh@' $out/pwndbg/lib/${python3.libPrefix}/subprocess.py

        # build pycache
        SOURCE_DATE_EPOCH=0 ${pkgsNative.python3}/bin/python3 -c "import compileall; compileall.compile_dir('$out', stripdir='$out', force=True);"
      '';
in
portable
