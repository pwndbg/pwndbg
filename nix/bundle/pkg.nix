{
  pkgs ? import <nixpkgs> { },
}:
let
  pfpmArchs = {
    "i686-linux" = "386";
    "x86_64-linux" = "amd64";

    "aarch64-linux" = "arm64";
    "armv7l-linux" = "armv7";

    "riscv64-linux" = "riscv64";
  };

  buildPackagePFPM =
    {
      drv ? null,
      config ? "nfpm.yaml",
      packager ? null, # apk|deb|rpm|archlinux
      preremove ? null,
      ...
    }@attrs:
    pkgs.stdenv.mkDerivation {
      name = "nfpm-${packager}-${drv.name}";
      buildInputs = [ pkgs.nfpm ];

      unpackPhase = "true";

      buildPhase =
        (pkgs.lib.optionalString (preremove != null) ''
          cp ${preremove} preremove.sh
        '')
        + ''
          mkdir -p ./dist
          ln -s ${drv} ./result
          export VERSION=${drv.meta.version}
          export ARCH=${pfpmArchs.${drv.meta.architecture}}
          nfpm pkg --config ${config} --packager ${packager} --target ./dist
        '';

      installPhase = ''
        mkdir -p $out
        cp -r ./dist/* $out
      '';
    };

  buildPackageTarball =
    {
      drv ? null,
      ...
    }@attrs:
    pkgs.stdenv.mkDerivation {
      name = "tarball-${drv.name}";
      buildInputs = [ pkgs.gnutar ];

      unpackPhase = "true";

      buildPhase = ''
        mkdir -p ./dist
        ln -s ${drv} ./result
        export DIST_TAR=$PWD/dist/${drv.meta.name}_${drv.meta.version}_${
          pfpmArchs.${drv.meta.architecture}
        }.tar.xz

        pushd ./result
        chmod +x bin/* || true
        chmod +x lib/ld-* || true
        tar cvfJ $DIST_TAR \
          --owner=0 --group=0 --mode=u+rw,uga+r \
          --mtime='1970-01-01' \
          .
        popd
      '';

      installPhase = ''
        mkdir -p $out
        cp -r ./dist/* $out
      '';
    };
in
{
  buildPackagePFPM = buildPackagePFPM;
  buildPackageTarball = buildPackageTarball;
}
