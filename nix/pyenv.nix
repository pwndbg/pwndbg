{
  pkgs,
  inputs,
  python3 ? pkgs.python3,
  isDev ? false,
  isLLDB ? false,
  ...
}:
let
  lib = pkgs.lib;
  hacks = pkgs.callPackage inputs.pyproject-nix.build.hacks { };
  workspace = inputs.uv2nix.lib.workspace.loadWorkspace { workspaceRoot = "${inputs.self}"; };

  pyprojectOverlay = workspace.mkPyprojectOverlay {
    sourcePreference = "sdist";
  };

  pkgsNeedSetuptools = [
    "capstone"
    "unicorn"
    "parso"
    "paramiko"
    "prompt"
    "colored"
    "pycparser"
    "gnureadline"
    "asttokens"
    "bcrypt"
    "cffi"
    "pexpect"
    "ipython"
    "intervaltree"
    "colored-traceback"
    "psutil"
    "prompt-toolkit"
    "pynacl"
    "pyserial"
    "pwntools"
    "pysocks"
    "requests"
    "six"
    "sortedcontainers"
    "python-dateutil"
    "tabulate"
    "wcwidth"
    "ropgadget"
    "zstandard"
    "certifi"
    "charset-normalizer"
    "executing"
    "jedi"
    "decorator"
    "mako"
    "markupsafe"
    "matplotlib-inline"
    "pure-eval"
    "pip"
    "pluggy"
    "stack-data"
    "unix-ar"
    "pyelftools"
    "types-requests"
    "types-tabulate"
    "types-pygments"
    "types-docutils"
    "types-gdb"
    "types-setuptools"
    "cryptography"
    "setuptools-scm"
    "trove-classifiers"
    "coverage"
    "mypy-extensions"
    "pytest"
    "pytest-cov"
    "mypy"
    "vermin"
  ];
  pkgsNeedFlitcore = [
    "typing-extensions"
    "idna"
    "packaging"
    "mdurl"
    "ptyprocess"
    "pathspec"
    "markdown-it-py"
  ];
  pkgsNeedHatchling = [
    "traitlets"
    "pygments"
    "urllib3"
    "plumbum"
    "rpyc"
    "iniconfig"
  ];
  pkgsNeedPoetry = [
    "pt"
    "rich"
    "sortedcontainers-stubs"
    "isort"
  ];

  genPkgsNeeded =
    listNeed: pydeps: final: prev:
    (lib.genAttrs listNeed (
      pkgName:
      prev.${pkgName}.overrideAttrs (old: {
        nativeBuildInputs =
          old.nativeBuildInputs
          ++ final.resolveBuildSystem (lib.genAttrs pydeps (name: [ ]));
      })
    ));

  isBuildWheel = old: lib.strings.hasSuffix ".whl" old.src.name;
  isBuildSource = old: !(isBuildWheel old);
  isCross = pkgs.stdenv.hostPlatform != pkgs.stdenv.buildPlatform;

  pyprojectOverrides1 =
    final: prev:
    (genPkgsNeeded pkgsNeedSetuptools [ "setuptools" ] final prev)
    // (genPkgsNeeded pkgsNeedFlitcore [ "flit-core" ] final prev)
    // (genPkgsNeeded pkgsNeedHatchling [ "hatchling" "hatch-vcs" ] final prev)
    // (genPkgsNeeded pkgsNeedPoetry [ "poetry-core" ] final prev);

  dummy = pkgs.runCommand "dummy" { } "mkdir $out";

  pyprojectOverrides2 = final: prev: {
    # paramiko is only used in pwntools for pwnlib.tubes.ssh
    paramiko = dummy;
    pip = dummy;

    psutil = pkgs.callPackage (
      {
        darwin,
        stdenv,
        python3,
        breakpointHook,
      }:
      prev.psutil.overrideAttrs (
        old:
        lib.optionalAttrs isCross {
          buildInputs = [ python3 ];
        }
        // lib.optionalAttrs stdenv.hostPlatform.isDarwin {
          NIX_CFLAGS_COMPILE = "-DkIOMainPortDefault=0";

          buildInputs =
            (old.buildInputs or [ ])
            ++ lib.optionals stdenv.hostPlatform.isx86_64 [
              darwin.apple_sdk.frameworks.CoreFoundation
            ]
            ++ [ darwin.apple_sdk.frameworks.IOKit ];
        }
      )
    ) { };

    capstone = pkgs.callPackage (
      {
        cmake,
        fixDarwinDylibNames,
        fetchFromGitHub,
        stdenv,
      }:
      prev.capstone.overrideAttrs (
        old:
        lib.optionalAttrs ((isBuildSource old) && stdenv.hostPlatform.isDarwin) {
          nativeBuildInputs = old.nativeBuildInputs ++ [
            cmake
            fixDarwinDylibNames
          ];

          preBuild = ''
            sed -i 's/^IS_APPLE := .*$/IS_APPLE := 1/' ./src/Makefile

            substituteInPlace ./setup.py \
                --replace-fail "import sys" "import sys; sys.argv.extend(('--plat-name', 'any'))" || true
          '';

          # See: https://github.com/capstone-engine/capstone/issues/2621
          postPatch = (
            let
              gitSrc = fetchFromGitHub {
                owner = "capstone-engine";
                repo = "capstone";
                rev = old.version;
                hash = "sha256-VGqqrixg7LaqRWTAEBzpC+gUTchncz3Oa2pSq8GLskI=";
              };
            in
            ''
              cp ${gitSrc}/capstone.pc.in src/
              cp ${gitSrc}/capstone-config.cmake.in src/
              cp ${gitSrc}/cmake_uninstall.cmake.in src/
              cp ${gitSrc}/CPackConfig.txt src/
              cp ${gitSrc}/CPackConfig.cmake src/
            ''
          );
        }
      )
    ) { };

    unicorn = pkgs.callPackage (
      {
        cmake,
        pkg-config,
        cctools,
        stdenv,
      }:
      prev.unicorn.overrideAttrs (
        old:
        lib.optionalAttrs ((isBuildSource old)) {
          nativeBuildInputs =
            old.nativeBuildInputs
            ++ [
              cmake
              pkg-config
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [
              cctools
            ];

          postPatch = lib.optionalString stdenv.hostPlatform.isDarwin ''
            substituteInPlace ./src/CMakeLists.txt \
                --replace-fail 'set(CMAKE_C_COMPILER "/usr/bin/cc")' 'set(CMAKE_C_COMPILER "${stdenv.cc}/bin/cc")' || true
          '';
        }
      )
    ) { };

    gnureadline = pkgs.callPackage (
      {
        python3,
        readline,
        ncurses,
      }:
      prev.gnureadline.overrideAttrs (
        old:
        let
          readlineStatic = readline.overrideAttrs (old': {
            configureFlags = (old'.configureFlags or [ ]) ++ [
              "--enable-static"
              "--disable-shared"
            ];
            postInstall = ''
              cp -v ./libhistory.a $out/lib/
              cp -v ./libreadline.a $out/lib/
            '';
          });
        in
        {
          preBuild = ''
            mkdir readline
            cp -rf ${readlineStatic.dev}/include/readline/*.h ./readline/
            cp -rf ${readlineStatic.out}/lib/*.a ./readline/
          '';
          buildInputs =
            [ ncurses ]
            ++ lib.optionals isCross [
              python3
            ];
        }
      )
    ) { };

    zstandard = pkgs.callPackage (
      { python3 }:
      prev.zstandard.overrideAttrs (old: {
        buildInputs =
          (old.buildInputs or [ ])
          ++ lib.optionals isCross [
            python3
          ];
      })
    ) { };
  };

  overlays = lib.composeManyExtensions [
    inputs.pyproject-build-systems.overlays.default
    pyprojectOverlay
    pyprojectOverrides1
    pyprojectOverrides2
    (final: prev: {
      pythonPkgsBuildHost = prev.pythonPkgsBuildHost.overrideScope (
        lib.composeManyExtensions [
          inputs.pyproject-build-systems.overlays.default
        ]
      );
    })
  ];

  baseSet = pkgs.callPackage inputs.pyproject-nix.build.packages {
    python = python3;
  };
  pythonSet = baseSet.overrideScope overlays;

  pyenv = pythonSet.mkVirtualEnv "pwndbg-env" {
    pwndbg =
      [ ]
      ++ lib.optionals isLLDB [
        "lldb"
      ]
      ++ lib.optionals isDev [
        "dev"
        "tests"
        # We don't need linters in "dev" build
        # "lint"
      ];
  };
in
pyenv
