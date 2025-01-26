{
  pkgs ? import <nixpkgs> { },
  pwndbg ? import ./pwndbg.nix { },
}:
let
  isLLDB = pwndbg.meta.isLLDB;
  lldb = pwndbg.meta.lldb;
  gdb = pwndbg.meta.gdb;
  python3 = pwndbg.meta.python3;
  pwndbgVenv = pwndbg.meta.pwndbgVenv;

  bundler = arg: (pkgs.callPackage ./bundle { } arg);

  ldName = pkgs.lib.readFile (
    pkgs.runCommand "pwndbg-bundle-ld-name-IFD" { nativeBuildInputs = [ pkgs.patchelf ]; } ''
      echo -n $(basename $(patchelf --print-interpreter "${gdb}/bin/gdb")) > $out
    ''
  );
  ldLoader = if pkgs.stdenv.isLinux then "\"$dir/lib/${ldName}\"" else "";

  commonEnvs =
    pkgs.lib.optionalString (pkgs.stdenv.isLinux && isLLDB) ''
      export LLDB_DEBUGSERVER_PATH="$dir/bin/lldb-server"
    ''
    + pkgs.lib.optionalString pkgs.stdenv.isLinux ''
      export TERMINFO_DIRS=${
        pkgs.lib.concatStringsSep ":" [
          # Fix issue Linux https://github.com/pwndbg/pwndbg/issues/2531
          "/etc/terminfo" # Debian, Fedora, Gentoo
          "/lib/terminfo" # Debian
          "/usr/share/terminfo" # upstream default, probably all FHS-based distros
          "/run/current-system/sw/share/terminfo" # NixOS
          "$dir/share/terminfo"
        ]
      }
    ''
    + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
      export TERMINFO_DIRS=${
        pkgs.lib.concatStringsSep ":" [
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
    # Darwin don't have gdbserver
    (pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
      "${pkgs.lib.getBin gdb}/bin/gdbserver"
      "exe/gdbserver"

      "${wrapperBin "exe/gdbserver"}"
      "bin/gdbserver"
    ])
    ++ [
      "${pkgs.lib.getBin gdb}/bin/gdb"
      "exe/gdb"

      "${gdb}/share/gdb/"
      "share/gdb/"

      "${pwndbgVenv}/lib/"
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

  pwndbgLldbBundled = bundler [
    "${pkgs.lib.getBin lldb}/bin/.lldb-wrapped"
    "exe/lldb"

    "${pkgs.lib.getBin lldb}/bin/lldb-server"
    "exe/lldb-server"

    "${pkgs.lib.getLib lldb}/lib/"
    "lib/"

    "${pwndbgVenv}/lib/"
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
  ];
  pwndbgBundled = if isLLDB then pwndbgLldbBundled else pwndbgGdbBundled;

  portable =
    pkgs.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.name;
          version = pwndbg.version;
          architecture = gdb.stdenv.targetPlatform.system;
        };
      }
      ''
        mkdir -p $out/pwndbg/
        # copy
        cp -rf ${pwndbgBundled}/* $out/pwndbg/

        # writable out
        chmod -R +w $out

        # copy extra files
        cp -rf ${pkgs.lib.getLib pkgs.ncurses}/share/terminfo/ $out/pwndbg/share/

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        substituteInPlace $out/pwndbg/lib/${python3.libPrefix}/subprocess.py --replace "'${pkgs.bash}/bin/sh'" "'/bin/sh'"

        # build pycache
        SOURCE_DATE_EPOCH=0 ${python3}/bin/python3 -c "import compileall; compileall.compile_dir('$out', stripdir='$out', force=True);"
      '';
in
portable
