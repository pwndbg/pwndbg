{
  pkgs,
  inputs,
  python3 ? pkgs.python3,
  isDev ? false,
  isLLDB ? false,
  isEditable ? false,
  ...
}:
let
  lib = pkgs.lib;
  hacks = pkgs.callPackage inputs.pyproject-nix.build.hacks { };
  workspace = inputs.uv2nix.lib.workspace.loadWorkspace { workspaceRoot = "${inputs.self}"; };

  pyprojectOverlay = workspace.mkPyprojectOverlay {
    sourcePreference = "sdist";
  };

  editableOverlay = workspace.mkEditablePyprojectOverlay {
    root = "$REPO_ROOT";
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
        stdenv,
      }:
      prev.capstone.overrideAttrs (
        old:
        lib.optionalAttrs (isBuildSource old) {
          nativeBuildInputs = old.nativeBuildInputs ++ [
            cmake
          ];
        }
      )
    ) { };

    unicorn = pkgs.callPackage (
      {
        cmake,
        pkg-config,
        cctools,
        stdenv,
        fetchFromGitHub,
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

            # Due to an issue with the Apple ARM64 Hypervisor on GitHub Actions,
            # we need to force the `sprr` register check.
            # Otherwise, Nix may cache broken builds.
            # See:
            # - https://github.com/actions/runner-images/issues/11127
            # - https://github.com/unicorn-engine/unicorn/issues/2033
            substituteInPlace ./src/qemu/configure \
                --replace-fail "have_sprr_mrs='no'" "have_sprr_mrs='yes'"
          '';
        }
        // lib.optionalAttrs stdenv.hostPlatform.isLoongArch64 {
          # Remove this block after upgrading to unicorn 2.2.0
          src = fetchFromGitHub {
            owner = "unicorn-engine";
            repo = "unicorn";
            rev = "e867b08c66544ddf8cd62c1e36e8ff35d32c3e77";
            hash = "sha256-vov6io2+RY8CZAoF0S00J2trlEEQHeMxw4HV8gm2Q2Y=";
          };
          sourceRoot = "source/bindings/python";
          preBuild = ''
            chmod -R +w ../../../
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
  editablePythonSet = pythonSet.overrideScope (
    lib.composeManyExtensions [
      inputs.pyproject-build-systems.overlays.default
      editableOverlay
      pyprojectOverrides1
      pyprojectOverrides2
      (final: prev: {
        pythonPkgsBuildHost = prev.pythonPkgsBuildHost.overrideScope (
          lib.composeManyExtensions [
            inputs.pyproject-build-systems.overlays.default
          ]
        );
      })
      (final: prev: {
        pwndbg = prev.pwndbg.overrideAttrs (old: {
          nativeBuildInputs =
            old.nativeBuildInputs
            ++ final.resolveBuildSystem {
              editables = [ ];
            };
        });
      })
    ]
  );

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

  pyenvEditable = editablePythonSet.mkVirtualEnv "pwndbg-editable-env" {
    pwndbg =
      [ ]
      ++ lib.optionals isLLDB [
        "lldb"
      ]
      ++ lib.optionals isDev [
        "dev"
        "tests"
      ];
  };
in
if isEditable then pyenvEditable else pyenv
