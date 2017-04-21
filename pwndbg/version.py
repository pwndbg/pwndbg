import os
import subprocess


def build_id():
    """
    Returns pwndbg commit id if git is available.
    """
    try:
        git_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.git')
        commit_id = subprocess.check_output(['git', '--git-dir', git_path, 'rev-parse', 'HEAD'])
        commit_id = commit_id[:8].decode('utf-8')

        return 'build: %s' % commit_id
    except:
        return ''

__version__ = '1.0.0'

b_id = build_id()

if b_id:
    __version__ += ' %s' % b_id

