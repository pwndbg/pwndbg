{
  description = "pwndbg";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.poetry2nix = {
    url = "github:nix-community/poetry2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      poetry2nix,
    }:
    let
      # Self contained packages for: Debian, RHEL-like (yum, rpm), Alpine, Arch packages
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
      forPortables = nixpkgs.lib.genAttrs [
        "deb"
        "rpm"
        "apk"
        "archlinux"
      ];

      pkgsBySystem = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [ poetry2nix.overlays.default ];
        }
      );
      pkgUtil = forAllSystems (system: import ./nix/bundle/pkg.nix { pkgs = pkgsBySystem.${system}; });

      portableDrv =
        system:
        import ./nix/portable.nix {
          pkgs = pkgsBySystem.${system};
          pwndbg = self.packages.${system}.pwndbg;
        };
      portableDrvs =
        system:
        forPortables (
          packager:
          pkgUtil.${system}.buildPackagePFPM {
            inherit packager;
            drv = portableDrv system;
            config = ./nix/bundle/nfpm.yaml;
            preremove = ./nix/bundle/preremove.sh;
          }
        );
      tarballDrv = system: {
        tarball = pkgUtil.${system}.buildPackageTarball { drv = portableDrv system; };
      };
    in
    {
      packages = forAllSystems (
        system:
        {
          pwndbg = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
          };
          default = self.packages.${system}.pwndbg;
          pwndbg-dev = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
            isDev = true;
          };
        }
        // (portableDrvs system)
        // (tarballDrv system)
      );

      devShells = forAllSystems (
        system:
        import ./nix/devshell.nix {
          pkgs = pkgsBySystem.${system};
          python3 = pkgsBySystem.${system}.python3;
          inputs.pwndbg = self;
        }
      );
    };
}
