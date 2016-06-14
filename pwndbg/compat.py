#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality, for determining whether we are
running under Python2 or Python3, and resolving any
inconsistencies which arise from this.
"""
from __future__ import print_function
from __future__ import unicode_literals

import sys

# Quickly determine which version is running
python2 = sys.version_info.major == 2
python3 = sys.version_info.major == 3

if python3:
    basestring = str
else:
    basestring = basestring
