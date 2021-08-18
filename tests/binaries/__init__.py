
import os

from . import div_zero_binary

path = os.path.dirname(__file__)


def get(x):
    return os.path.join(path, x)
