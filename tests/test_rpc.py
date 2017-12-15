# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from .common import run_gdb_with_script, server

def test_eval():
    assert server.eval('7') == 7

def test_example():
    assert server.gdb.parse_and_eval('7')

def test_arch_pack():
    result = server.pwndbg.arch.pack(0xdeadbeef)
    assert result == bytearray(b'\xef\xbe\xad\xde')

