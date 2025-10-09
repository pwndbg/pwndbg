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

  macosQuarantine = lib.optionalString pkgs.stdenv.isDarwin ''
    libpython="libpython${python3.pythonVersion}.dylib"

    if command -v xattr >/dev/null 2>&1 && command -v grep >/dev/null 2>&1; then
      if xattr -x "$dir/lib/$libpython" 2>/dev/null | grep -q com.apple.quarantine; then
        echo "Error: The pwndbg is marked as quarantined by macOS."
        echo "To fix this, run the following command:"
        echo ""
        echo "  xattr -rd com.apple.quarantine \"$dir\""
        echo ""
        exit 1
      fi
    fi
  '';

  wrapperBinPy =
    file:
    pkgs.writeScript "pwndbg-wrapper-bin-py" ''
      #!/bin/sh
      dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
      ${commonEnvs}
      ${macosQuarantine}
      exec ${ldLoader} "$dir/exe/python3" "$dir/${file}" "$@"
    '';
  wrapperBin =
    file:
    pkgs.writeScript "pwndbg-wrapper-bin" ''
      #!/bin/sh
      dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
      ${commonEnvs}
      ${macosQuarantine}
      exec ${ldLoader} "$dir/${file}" "$@"
    '';

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

      "${wrapperBin "exe/gdb"}"
      "bin/gdb"

      "${gdb}/share/gdb/"
      "share/gdb/"

      "${python3}/bin/python3"
      "exe/python3"

      "${pwndbgVenv}/lib/"
      "lib/"

      "${python3}/lib/"
      "lib/"

      "${pwndbgVenv}/bin/pwndbg"
      "exe/pwndbg"

      "${wrapperBinPy "exe/pwndbg"}"
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

      "${wrapperBin "exe/lldb-server"}"
      "bin/lldb-server"

      "${wrapperBin "exe/lldb"}"
      "bin/lldb"

      "${pwndbgVenv}/bin/pwndbg-lldb"
      "exe/pwndbg-lldb"

      "${wrapperBinPy "exe/pwndbg-lldb"}"
      "bin/pwndbg-lldb"
    ]
  );
  pwndbgBundled = if isLLDB then pwndbgLldbBundled else pwndbgGdbBundled;

  portable =
    pkgsNative.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.name;
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

        # remove unneeded dirs
        rm -rf $out/pwndbg/lib/pkgconfig
        find $out/pwndbg/lib/${python3.libPrefix}/ -type d -name "__pycache__" -exec rm -rf {} +
        find $out/pwndbg/lib/${python3.libPrefix}/ -maxdepth 1 -type d -name "config-*" -exec rm -rf {} +

        # EXTERNALLY-MANAGED info
        echo -e "[externally-managed]\nError=This is a pwndbg-portable installation.\n Installing additional dependencies is not supported." > $out/pwndbg/lib/${python3.libPrefix}/EXTERNALLY-MANAGED

        # copy extra files
        mkdir -p $out/pwndbg/share/
        cp -rf ${lib.getLib pkgs.ncurses}/share/terminfo/ $out/pwndbg/share/

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        sed -i 's@/nix/store/.*/bin/sh@/bin/sh@' $out/pwndbg/lib/${python3.libPrefix}/subprocess.py

        # remove /nix/store references in all files
        find $out/pwndbg/ -type f -exec ${pkgsNative.nukeReferences}/bin/nuke-refs {} +

        # build pycache
        SOURCE_DATE_EPOCH=0 ${pkgsNative.python3}/bin/python3 -c "import compileall; compileall.compile_dir('$out', stripdir='$out', force=True);"
      '';
in
portable
