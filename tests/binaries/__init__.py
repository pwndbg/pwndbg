from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os

from . import old_bash

path = os.path.dirname(__file__)


def get(x):
    return os.path.join(path, x)
