from __future__ import annotations

import os
import subprocess


def build_id() -> str:
    """
    Returns pwndbg commit id and its relative commit date if git is available.
    """
    pwndbg_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    # If we install pwndbg into site-packages, then `.pwndbg_root` is missing.
    if not os.path.exists(os.path.join(pwndbg_dir, ".pwndbg_root")):
        return ""

    try:
        git_path = os.path.join(pwndbg_dir, ".git")
        # %h -> abbreviated commit hash, %cr -> committer date, relative
        cmd = ["git", "--git-dir", git_path, "log", "-1", "--format=%h (%cr)"]

        commit_info = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        return "build: {}".format(commit_info.decode("utf-8").strip("\n"))

    except (OSError, subprocess.CalledProcessError):
        # OSError -> no git in $PATH
        # CalledProcessError -> git return code != 0
        return ""


__version__ = "2026.09.15"

b_id = build_id()

if b_id:
    __version__ += f" {b_id}"
