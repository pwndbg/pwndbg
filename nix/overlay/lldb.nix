{
  prev,
  ...
}:
let
  # Copied from: https://github.com/NixOS/nixpkgs/pull/375484
  isCross = prev.stdenv.hostPlatform != prev.stdenv.buildPlatform;
  lib = prev.lib;

  tblgen = prev.pkgsBuildHost.callPackage ./tblgen.nix {
    release_version = builtins.elemAt (lib.strings.splitString "." prev.pwndbg_lldb.version) 0;
    version = prev.pwndbg_lldb.version;
    monorepoSrc = prev.pwndbg_lldb.passthru.monorepoSrc;
  };

  drv =
    if !isCross then
      prev.pwndbg_lldb
    else
      prev.callPackage (
        {
          llvmPackages,
          llvmPackages_20,
          cmake,
          which,
          swig,
          lit,
          makeWrapper,
          ninja,
          python3,
          lua5_3,
        }:
        (prev.pwndbg_lldb.override {
          stdenv = llvmPackages.stdenv;
          # Out-of-memory when building with debuginfo enabled.. build use more than 32gb+ ram
          libclang = llvmPackages_20.libclang.overrideAttrs (old: {
            separateDebugInfo = false;
          });
        }).overrideAttrs
          (old: {
            patches = (old.patches or [ ]) ++ [
              ./lldb-fix-cross-python.patch
            ];
            nativeBuildInputs = [
              cmake
              which
              swig
              makeWrapper
              ninja
            ];
            buildInputs = (old.buildInputs ++ [ ]) ++ [
              python3
              lua5_3
            ];
            cmakeFlags = (old.cmakeFlags ++ [ ]) ++ [
              "-DPYTHON_HOME=${python3}"
              "-DPython3_EXECUTABLE_NATIVE=${python3.pythonOnBuildForHost.interpreter}"
              "-DLLVM_TABLEGEN=${tblgen}/bin/llvm-tblgen"
              "-DCLANG_TABLEGEN=${tblgen}/bin/clang-tblgen"
              "-DLLDB_TABLEGEN_EXE=${tblgen}/bin/lldb-tblgen"
            ];
          })
      ) { };
in
drv
