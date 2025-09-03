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


def get_venv_path(src_root: Path):
    venv_path_env = os.environ.get("PWNDBG_VENV_PATH")
    if venv_path_env:
        return Path(venv_path_env).expanduser().resolve()
    else:
        return src_root / ".venv"


def main() -> None:
    src_root = Path(__file__).parent.resolve()
    venv_path = get_venv_path(src_root)
    if not venv_path.exists():
        print(
            f"Cannot find Pwndbg virtualenv directory: {venv_path}. Please re-run setup.sh",
            flush=True,
        )
        os._exit(1)

    fixup_paths(src_root, venv_path)
    from pwndbginit.gdbinit import main_try

    main_try()


main()
