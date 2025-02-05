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

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      ...
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
              inputs = inputs;
            };
            pwndbg-dev = import ./nix/pwndbg.nix {
              pkgs = pkgsBySystem.${systemfix};
              python3 = pkgsBySystem.${systemfix}.python3;
              gdb = pkgsBySystem.${systemfix}.gdb;
              inputs = inputs;
              isDev = true;
            };
          }
        )
        // {
          pwndbg-lldb = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            lldb = pkgsBySystem.${system}.lldb_19;
            inputs = inputs;
            isLLDB = true;
          };
          pwndbg-lldb-dev = import ./nix/pwndbg.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            lldb = pkgsBySystem.${system}.lldb_19;
            inputs = inputs;
            isDev = true;
            isLLDB = true;
          };
          pyenv-sdist = import ./nix/pyenv.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            inputs = inputs;
            preferWheel = false;
          };
          pyenv-wheel = import ./nix/pyenv.nix {
            pkgs = pkgsBySystem.${system};
            python3 = pkgsBySystem.${system}.python3;
            inputs = inputs;
            preferWheel = true;
          };
          pyenv-sdist-riscv64 = import ./nix/pyenv.nix {
            pkgs = pkgsBySystem.${system}.pkgsCross.riscv64;
            python3 = pkgsBySystem.${system}.python3;
            inputs = inputs;
            preferWheel = false;
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
          inputs = inputs;
          isLLDB = true;
        }
      );
      formatter = forAllSystems (system: pkgsBySystem.${system}.nixfmt-rfc-style);
    };
}
