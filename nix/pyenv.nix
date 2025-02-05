{
  pkgs,
  python3,
  inputs,
  isDev ? false,
  isLLDB ? false,
  preferWheel ? false,
  ...
}:
let
  lib = pkgs.lib;
  hacks = pkgs.callPackage inputs.pyproject-nix.build.hacks { };
  workspace = inputs.uv2nix.lib.workspace.loadWorkspace { workspaceRoot = "${inputs.self}"; };

  pyprojectOverlay = workspace.mkPyprojectOverlay {
    sourcePreference = if preferWheel then "wheel" else "sdist";
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

  pyprojectOverrides1 =
    final: prev:
    (genPkgsNeeded pkgsNeedSetuptools [ "setuptools" ] final prev)
    // (genPkgsNeeded pkgsNeedFlitcore [ "flit-core" ] final prev)
    // (genPkgsNeeded pkgsNeedHatchling [ "hatchling" "hatch-vcs" ] final prev)
    // (genPkgsNeeded pkgsNeedPoetry [ "poetry-core" ] final prev);

  pyprojectOverrides2 = final: prev: {
    cryptography =
      if (isBuildWheel prev.cryptography) then
        prev.cryptography
      else
        (
          (hacks.importCargoLock {
            prev = prev.cryptography;
            cargoRoot = "src/rust";
          }).overrideAttrs
          (old: {
            nativeBuildInputs =
              old.nativeBuildInputs
              ++ final.resolveBuildSystem {
                maturin = [ ];
                cffi = [ ];
                pycparser = [ ];
              };
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.openssl ];
          })
        );

    # TODO: check why `cffi` is broken only for macOS
    cffi = prev.cffi.overrideAttrs (old: {
      nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.pkg-config ];
      buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.libffi ];

      prePatch = lib.optionalString ((isBuildSource old) && pkgs.stdenv.hostPlatform.isDarwin) ''
        # Remove setup.py impurities
        substituteInPlace setup.py --replace-warn "'-iwithsysroot/usr/include/ffi'" ""
        substituteInPlace setup.py --replace-warn "'/usr/include/ffi'," ""
        substituteInPlace setup.py --replace-warn '/usr/include/libffi' '${lib.getDev pkgs.libffi}/include'
      '';
    });

    psutil = prev.psutil.overrideAttrs (
      old:
      pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
        stdenv = pkgs.overrideSDK pkgs.stdenv "11.0";
        NIX_CFLAGS_COMPILE = "-DkIOMainPortDefault=0";

        buildInputs =
          (old.buildInputs or [ ])
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isx86_64 [
            pkgs.darwin.apple_sdk.frameworks.CoreFoundation
          ]
          ++ [ pkgs.darwin.apple_sdk.frameworks.IOKit ];
      }
    );

    capstone = prev.capstone.overrideAttrs (
      old:
      pkgs.lib.optionalAttrs ((isBuildSource old) && pkgs.stdenv.hostPlatform.isDarwin) {
        nativeBuildInputs = old.nativeBuildInputs ++ [
          pkgs.cmake
          pkgs.fixDarwinDylibNames
        ];

        preBuild = ''
          sed -i 's/^IS_APPLE := .*$/IS_APPLE := 1/' ./src/Makefile

          substituteInPlace ./setup.py \
              --replace-fail "import sys" "import sys; sys.argv.extend(('--plat-name', 'any'))" || true
        '';

        # See: https://github.com/capstone-engine/capstone/issues/2621
        postPatch = (
          let
            gitSrc = pkgs.fetchFromGitHub {
              owner = "capstone-engine";
              repo = "capstone";
              rev = old.version;
              hash = "sha256-LZ10czBn5oaKMHQ8xguC6VZa7wvEgPRu6oWt/22QaDs=";
            };
          in
          ''
            cp ${gitSrc}/capstone.pc.in src/
            cp ${gitSrc}/capstone-config.cmake.in src/
            cp ${gitSrc}/cmake_uninstall.cmake.in src/
          ''
        );
      }
    );

    unicorn = prev.unicorn.overrideAttrs (
      old:
      pkgs.lib.optionalAttrs ((isBuildSource old)) {
        nativeBuildInputs =
          old.nativeBuildInputs
          ++ [
            pkgs.cmake
            pkgs.pkg-config
          ]
          ++ lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
            pkgs.cctools
          ];

        postPatch =
          ''
            substituteInPlace ./setup.py \
                --replace-fail "import sys" "import sys; sys.argv.extend(('--plat-name', 'any'))" || true

            # See: https://github.com/unicorn-engine/unicorn/issues/2015
            substituteInPlace ./src/CMakeLists.txt \
                --replace-fail 'include(cmake/bundle_static.cmake)' 'include(bundle_static.cmake)' || true
          ''
          + lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
            substituteInPlace ./src/CMakeLists.txt \
                --replace-fail 'set(CMAKE_C_COMPILER "/usr/bin/cc")' 'set(CMAKE_C_COMPILER "${pkgs.stdenv.cc}/bin/cc")' || true
          '';
      }
    );

    gnureadline = prev.gnureadline.overrideAttrs (old: {
      buildInputs = (old.buildInputs or [ ]) ++ [
        pkgs.ncurses
      ];
    });
  };

  overlays = lib.composeManyExtensions [
    inputs.pyproject-build-systems.overlays.default
    pyprojectOverlay
    pyprojectOverrides1
    pyprojectOverrides2
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
