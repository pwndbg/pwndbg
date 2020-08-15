
import os

from . import old_bash

path = os.path.dirname(__file__)


def get(x):
    return os.path.join(path, x)
