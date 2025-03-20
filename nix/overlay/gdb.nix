{
  prev,
  ...
}:
let
  # Copied from: https://github.com/NixOS/nixpkgs/pull/275731
  isCross = prev.stdenv.hostPlatform != prev.stdenv.buildPlatform;

  drv =
    if !isCross then
      prev.pwndbg_gdb.overrideAttrs (
        old:
        prev.lib.optionalAttrs (prev.stdenv.targetPlatform.isDarwin && prev.stdenv.targetPlatform.isAarch64)
          {
            configureFlags = [
              "--target=arm-none-eabi"
            ] ++ old.configureFlags;
            configurePlatforms = [ ];
            meta.badPlatforms = [ ];
          }
      )
    else
      (prev.pwndbg_gdb.override { pythonSupport = true; }).overrideAttrs (old: {
        patches = (old.patches or [ ]) ++ [
          ./gdb-fix-cross-python.patch
        ];
        configureFlags = (old.configureFlags ++ [ ]) ++ [
          "--with-python=${prev.python3.pythonOnBuildForHost.interpreter}"
        ];
      });
in
drv
