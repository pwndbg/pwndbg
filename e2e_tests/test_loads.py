#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from . import common

import re


BASH_BIN = './e2e_tests/corefiles/bash/binary'
BASH_CORE = './e2e_tests/corefiles/bash/core'


def test_loads_pure_gdb_without_crashing():
    output = common.run_gdb_with_script()
    assert output == '', "The output was: %r" % output

def test_loads_binary_without_crashing():
    output = common.run_gdb_with_script(binary=BASH_BIN)
    assert output == '', "The output was: %r" % output


def test_loads_binary_with_core_without_crashing():
    output = common.run_gdb_with_script(binary=BASH_BIN, core=BASH_CORE)
    assert output == '', "The output was: %r" % output


def test_loads_core_without_crashing():
    output = common.run_gdb_with_script(core=BASH_CORE)
    assert output == '', "The output was: %r" % output

