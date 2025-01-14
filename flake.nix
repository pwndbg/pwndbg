{
  description = "pwndbg";

  nixConfig = {
    extra-substituters = [
      "https://pwndbg.cachix.org"
    ];
    extra-trusted-public-keys = [
      "pwndbg.cachix.org-1:HhtIpP7j73SnuzLgobqqa8LVTng5Qi36sQtNt79cD3k="
    ];
  };

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

      overlayDarwin =
        final: prev:
        nixpkgs.lib.optionalAttrs prev.stdenv.isDarwin {
          gdb = prev.gdb.override {
            # Darwin version of libiconv causes issues with our portable build
            libiconv = prev.pkgsStatic.libiconvReal;
          };
        };
      pkgsBySystem = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [
            poetry2nix.overlays.default
            overlayDarwin
          ];
        }
      );
      pkgUtil = forAllSystems (system: import ./nix/bundle/pkg.nix { pkgs = pkgsBySystem.${system}; });

      portableDrvLldb =
        system:
        import ./nix/portable.nix {
          pkgs = pkgsBySystem.${system};
          pwndbg = self.packages.${system}.pwndbg-lldb;
        };
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
        tarball-lldb = pkgUtil.${system}.buildPackageTarball { drv = portableDrvLldb system; };
      };
    in
    {
      packages = forAllSystems (
        system:
        {
          default = self.packages.${system}.pwndbg;
        }
        // (
          let
            systemfix = if (system == "aarch64-darwin") then "x86_64-darwin" else system;
          in
          {
            pwndbg = import ./nix/pwndbg.nix {
              pkgs = pkgsBySystem.${systemfix};
              python3 = pkgsBySystem.${systemfix}.python3;
              gdb = pkgsBySystem.${systemfix}.gdb;
              inputs.pwndbg = self;
            };
            pwndbg-dev = import ./nix/pwndbg.nix {
              pkgs = pkgsBySystem.${systemfix};
              python3 = pkgsBySystem.${systemfix}.python3;
              gdb = pkgsBySystem.${systemfix}.gdb;
              inputs.pwndbg = self;
              isDev = true;
            };
          }
        )
        // {
          pwndbg-lldb = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            gdb = pkgsBySystem.${system}.gdb;
            inputs.pwndbg = self;
            isDev = true;
            isLLDB = true;
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
          isLLDB = true;
        }
      );
      formatter = forAllSystems (system: pkgsBySystem.${system}.nixfmt-rfc-style);
    };
}
