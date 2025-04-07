# This license covers everything within this project, except for a few pieces
# of code that we either did not write ourselves or which we derived from code
# that we did not write ourselves. These few pieces have their license specified
# in a header, or by a file called LICENSE.txt, which will explain exactly what
# it covers. The few relevant pieces of code are all contained inside these
# directories:
#
# - pwnlib/constants/
# - pwnlib/data/
#
#
# Copyright (c) 2015 Gallopsled and Zach Riggle
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
from __future__ import annotations

import os
import stat
from typing import Set


def which(name: str, all: bool = False) -> Set[str] | str | None:
    """which(name, flags = os.X_OK, all = False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is `True` the set of all found locations is returned, else
    the first occurrence or `None` is returned.

    Arguments:
      name: The file to search for.
      all:  Whether to return all locations where `name` was found.

    Returns:
      If `all` is `True` the set of all locations where `name` was found,
      else the first location or `None` if not found.

    Example:
      >>> which('sh')
      '/bin/sh'
    """
    # If name is a path, do not attempt to resolve it.
    if os.path.sep in name:
        return name

    isroot = os.getuid() == 0
    out: Set[str] = set()
    try:
        path = os.environ["PATH"]
    except KeyError:
        print("Environment variable $PATH is not set")
        return None

    for p in path.split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, os.X_OK):
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            # work around this issue: https://bugs.python.org/issue9311
            if isroot and not st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if all:
                out.add(p)
            else:
                return p
    if all:
        return out
    else:
        return None
