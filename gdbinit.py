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


def is_system_installation(src_root: Path) -> bool:
    # NOTE: Keep this in sync with `pwndbginit.common.is_system_installation`.
    # It is intentionally duplicated here so that `gdbinit.py` does not import the
    # `pwndbginit` package before `fixup_paths()` has corrected `sys.path`. Otherwise,
    # a system-wide Pwndbg installation (e.g. an Arch `pwndbg` package in the global
    # site-packages) could shadow the source checkout that is being sourced, leading
    # to a confusing mix of modules loaded from two different locations. See:
    # https://github.com/pwndbg/pwndbg/issues/3963
    #
    # If pwndbg is installed in `/venv/lib/pythonX.Y/site-packages/pwndbg/`,
    # the `.pwndbg_root` file will not exist because `src_root` will point to the
    # `/venv/lib/pythonX.Y/site-packages/` directory, not the original source directory.
    #
    # However, if pwndbg is installed in editable mode (our recommended way), this file
    # will exist, and the condition will be False, allowing auto-update.
    return not (src_root / ".pwndbg_root").exists()


def get_venv_path(src_root: Path):
    venv_path_env = os.environ.get("PWNDBG_VENV_PATH")
    if venv_path_env:
        return Path(venv_path_env).expanduser().resolve()

    # Handle case when `gdbinit.py` is running from inside venv, eg: `venv/share/pwndbg/gdbinit.py`
    # See, example usage: https://github.com/pwndbg/pwndbg/pull/3737
    if (
        src_root.parent.name == "share"
        and src_root.name == "pwndbg"
        and (src_root / "../../pyvenv.cfg").exists()
    ):
        return src_root.parent.parent

    return src_root / ".venv"


def main() -> None:
    # Check if pwndbg was already loaded from `pwndbg` binary
    if "pwndbg" in sys.modules and hasattr(sys.modules["pwndbg"], "_is_loaded_from_pwndbg"):
        print(
            "\033[90m~/.gdbinit: Skipped loading Pwndbg from `source path/gdbinit.py` - already loaded.\033[0m",
            flush=True,
        )
        return

    src_root = Path(__file__).parent.resolve()

    # If Pwndbg is installed by a distro package manager, skip the virtualenv check.
    # `is_system_installation` is inlined (not imported from `pwndbginit`) on purpose so
    # we don't import the `pwndbginit` package before `fixup_paths()` fixes `sys.path`.
    skip_venv = is_system_installation(src_root)

    if not skip_venv:
        venv_path = get_venv_path(src_root)
        if not venv_path.exists():
            print(
                f"\nCannot find Pwndbg virtualenv directory: {venv_path}. Please (re-)run setup.sh from the Pwndbg source folder.\n"
                "(see https://pwndbg.re/dev/setup/#installing-from-source)",
                flush=True,
            )
            os._exit(1)

        fixup_paths(src_root, venv_path)

    from pwndbginit.gdbinit import main_try

    main_try()


main()
