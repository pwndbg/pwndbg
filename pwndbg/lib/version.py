import os
import subprocess


def build_id() -> str:
    """
    Returns pwndbg commit id if git is available.
    """
    pwndbg_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    assert os.path.exists(os.path.join(pwndbg_dir, "gdbinit.py"))

    try:
        git_path = os.path.join(pwndbg_dir, ".git")
        cmd = ["git", "--git-dir", git_path, "rev-parse", "--short", "HEAD"]

        commit_id = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        return "build: %s" % commit_id.decode("utf-8").strip("\n")

    except (OSError, subprocess.CalledProcessError):
        # OSError -> no git in $PATH
        # CalledProcessError -> git return code != 0
        return ""


__version__ = "2023.03.19"

b_id = build_id()

if b_id:
    __version__ += f" {b_id}"
