from __future__ import annotations

import os

path = os.path.dirname(__file__)


def get(x):
    return os.path.join(path, x)
