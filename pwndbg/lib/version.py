import os
import subprocess


def build_id():  # type: () -> str
    """
    Returns pwndbg commit id if git is available.
    """
    try:
        git_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".git")
        cmd = ["git", "--git-dir", git_path, "rev-parse", "--short", "HEAD"]

        commit_id = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        return "build: %s" % commit_id.decode("utf-8").strip("\n")

    except (OSError, subprocess.CalledProcessError):
        # OSError -> no git in $PATH
        # CalledProcessError -> git return code != 0
        return ""


__version__ = "1.1.1"

b_id = build_id()

if b_id:
    __version__ += " %s" % b_id
