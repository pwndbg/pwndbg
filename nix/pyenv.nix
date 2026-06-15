{
  pkgs,
  inputs,
  python3 ? pkgs.python3,
  isDev ? false,
  isEditable ? false,
  groups,
  ...
}:
let
  lib = pkgs.lib;
  hacks = pkgs.callPackage inputs.pyproject-nix.build.hacks { };
  workspace = inputs.uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./..; };

  pyprojectOverlay = workspace.mkPyprojectOverlay {
    sourcePreference = "sdist";
  };

  editableOverlay = workspace.mkEditablePyprojectOverlay {
    root = "$REPO_ROOT";
  };

  pkgsNeedSetuptools = [
    "capstone"
    "capstone6pwndbg"
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
    "types-psutil"
    "types-gdb"
    "types-setuptools"
    "cryptography"
    "setuptools-scm"
    "trove-classifiers"
    "coverage"
    "mypy-extensions"
    "pytest"
    "mypy"
    "vermin"
    # decomp2dbg deps
    "decomp2dbg"
    "ghidra-bridge"
    "jfx-bridge"
    "tqdm"
    "toml"
    "libbs"
    "networkx"
    "jpype1"
    "pyhidra"
    "ply"
    # end of decomp2dbg deps
    "niche-elf"
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
    # decomp2dbg deps
    "decomp2dbg"
    "filelock"
    "platformdirs"
    # end of decomp2dbg deps
  ];
  pkgsNeedPoetry = [
    "pt"
    "rich"
    "sortedcontainers-stubs"
  ];

  genPkgsNeeded =
    listNeed: pydeps: final: prev:
    (lib.genAttrs listNeed (
      pkgName:
      prev.${pkgName}.overrideAttrs (old: {
        nativeBuildInputs =
          old.nativeBuildInputs ++ final.resolveBuildSystem (lib.genAttrs pydeps (name: [ ]));
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
    uv = dummy;

    # ziglang is only supported on few platforms
    ziglang = prev.ziglang.override {
      sourcePreference = "wheel";
    };

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
          postPatch = ''
            # stick to the old SDK name for now
            # https://developer.apple.com/documentation/iokit/kiomasterportdefault/
            # https://developer.apple.com/documentation/iokit/kiomainportdefault/
            substituteInPlace psutil/arch/osx/cpu.c \
              --replace-fail kIOMainPortDefault kIOMasterPortDefault
          '';
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

    capstone6pwndbg = pkgs.callPackage (
      {
        cmake,
        stdenv,
      }:
      prev.capstone6pwndbg.overrideAttrs (
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
        fetchpatch,
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
                --replace-fail 'set(CMAKE_C_COMPILER "/usr/bin/cc")' 'set(CMAKE_C_COMPILER "${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc")'
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
          buildInputs = [
            ncurses
          ]
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

    jfx-bridge = pkgs.callPackage (
      { stdenv }:
      prev.jfx-bridge.overrideAttrs (old: {
        postPatch = ''
          substituteInPlace ./setup.py \
            --replace-fail 'git describe --tags' 'echo ${old.version}'
        '';
      })
    ) { };

    jpype1 = pkgs.callPackage (
      { python3 }:
      prev.jpype1.overrideAttrs (old: {
        buildInputs =
          (old.buildInputs or [ ])
          ++ lib.optionals isCross [
            python3
          ];
      })
    ) { };

    ghidra-bridge = pkgs.callPackage (
      { }:
      prev.ghidra-bridge.overrideAttrs (old: {
        postPatch = ''
          substituteInPlace ./setup.py \
            --replace-fail 'git describe --tags' 'echo ${old.version}'
        '';
      })
    ) { };

    gdb-for-pwndbg = pkgs.callPackage (
      { python3, autoPatchelfHook }:
      prev.gdb-for-pwndbg.overrideAttrs (old: {
        nativeBuildInputs = builtins.filter (x: x != autoPatchelfHook) old.nativeBuildInputs;
        postFixup = ''
          for f in ${python3}/lib/libpython*; do
            name=$(basename "$f")
            ln -s "$f" "$out/lib/$name";
          done
        '';
      })
    ) { };

    lldb-for-pwndbg = pkgs.callPackage (
      { python3, autoPatchelfHook }:
      prev.lldb-for-pwndbg.overrideAttrs (old: {
        nativeBuildInputs = builtins.filter (x: x != autoPatchelfHook) old.nativeBuildInputs;
        postFixup = ''
          for f in ${python3}/lib/libpython*; do
            name=$(basename "$f")
            ln -s "$f" "$out/lib/$name";
          done
        '';
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
    stdenv = pkgs.stdenv.override {
      targetPlatform = pkgs.stdenv.targetPlatform // {
        # See https://en.wikipedia.org/wiki/MacOS_version_history#Releases for more background on version numbers.
        darwinSdkVersion = "13.0";
      };
    };
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
      ++ lib.optionals isDev [
        "dev"
        "tests"
        # We don't need linters in "dev" build
        # "lint"
      ]
      ++ groups;
  };

  pyenvEditable = editablePythonSet.mkVirtualEnv "pwndbg-editable-env" {
    pwndbg =
      [ ]
      ++ lib.optionals isDev [
        "dev"
        "tests"
      ]
      ++ groups;
  };

  final = (if isEditable then pyenvEditable else pyenv).overrideAttrs (old: {
    meta = {
      python3 = python3;
    };
  });
in
final
