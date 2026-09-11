from __future__ import annotations

import os
import site
import sys
from glob import glob
from pathlib import Path


def fixup_paths(src_root: Path, venv_path: Path):
    site_pkgs_path = glob(str(venv_path / "lib/*/site-packages"))[0]

    # add virtualenv's site-packages to sys.path and run .pth files
    site.addsitedir(site_pkgs_path)

    # remove existing, system-level site-packages from sys.path
    for site_packages in site.getsitepackages():
        if site_packages in sys.path:
            sys.path.remove(site_packages)

    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    bin_path = str(venv_path / "bin")
    os.environ["PATH"] = bin_path + os.pathsep + os.environ.get("PATH", "")

    # Add pwndbg directory to sys.path so it can be imported
    sys.path.insert(0, str(src_root))

    # Push virtualenv's site-packages to the front
    if site_pkgs_path in sys.path:
        sys.path.remove(site_pkgs_path)
    sys.path.insert(1, site_pkgs_path)

    # sys.prefix must be changed to point to the virtual environment.
    # This is what python expect: https://docs.python.org/3/library/sys.html#sys.prefix
    sys.prefix = str(venv_path)
    sys.exec_prefix = str(venv_path)


def in_venv_share_dir(src_root: Path) -> bool:
    # gdbinit.py installed as <venv>/share/pwndbg/gdbinit.py via wheel shared-data.
    # See https://github.com/pwndbg/pwndbg/pull/3737
    return (
        src_root.parent.name == "share"
        and src_root.name == "pwndbg"
        and (src_root.parent.parent / "pyvenv.cfg").exists()
    )


def get_venv_path_if_fixup_needed(src_root: Path) -> Path | None:
    venv_path_env = os.environ.get("PWNDBG_VENV_PATH")
    if venv_path_env:
        return Path(venv_path_env).expanduser().resolve()

    if in_venv_share_dir(src_root):
        return src_root.parent.parent

    # Handle case when you use source /path/to/pwndbg-git-dir/gdbinit.py + .pwndbg_root, only venv
    if (src_root / ".pwndbg_root").exists():
        return src_root / ".venv"

    # Handle case when you use source /path/to/not-pwndbg-dir/gdbinit.py + without venv, only system pwndbg
    # Example: handle Archlinux case: source /usr/share/pwndbg/gdbinit.py
    return None


def main() -> None:
    # Check if pwndbg was already loaded
    # Can happen if you run `pwndbg /bin/sh` and have `source /path/to/gdbinit.py`
    # in your `~/.gdbinit`.
    if "pwndbg" in sys.modules and hasattr(sys.modules["pwndbg"], "_is_loaded_from_pwndbg"):
        print(
            "\033[90m~/.gdbinit: Skipped loading Pwndbg from `source path/gdbinit.py` - already loaded.\033[0m",
            flush=True,
        )
        return

    src_root = Path(__file__).parent.resolve()

    # If Pwndbg is installed by a distro package manager, we don't have a virtualenv that requires path fixups
    # Note we do NOT import `pwndbginit` package before `fixup_paths()` has corrected `sys.path`. Otherwise,
    # a system-wide Pwndbg installation (e.g. an Arch `pwndbg` package in the global
    # site-packages) could shadow the source checkout that is being sourced, leading
    # to a confusing mix of modules loaded from two different locations. See:
    # https://github.com/pwndbg/pwndbg/issues/3963

    venv_dir = get_venv_path_if_fixup_needed(src_root)

    if venv_dir is not None:
        if not venv_dir.exists():
            print(
                f"\nCannot find Pwndbg virtualenv directory: {venv_dir}. Please (re-)run setup.sh from the Pwndbg source folder.\n"
                "(see https://pwndbg.re/dev/setup/#installing-from-source)",
                flush=True,
            )
            os._exit(1)

        fixup_paths(src_root, venv_dir)

    from pwndbginit.gdbinit import main_try

    main_try()


main()
