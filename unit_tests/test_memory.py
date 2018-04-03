from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pytest
import pwndbg.memory
import pwndbg.stack


@pytest.fixture
def program_entry():
    gdb.execute('entry')


@pytest.fixture
def stack_addr(program_entry):
    return next(iter(pwndbg.stack.stacks.values())).vaddr


def test_memory_read_write(stack_addr):
    # Testing write(addr, str)
    val = 'X' * 50
    pwndbg.memory.write(stack_addr, val)
    assert pwndbg.memory.read(stack_addr, len(val)+1) == bytearray(b'X'*50 + b'\x00')

    # Testing write(addr, bytearray)
    val = bytearray('Y' * 10, 'utf8')
    pwndbg.memory.write(stack_addr, val)
    assert pwndbg.memory.read(stack_addr, len(val)+4) == val + bytearray(b'XXXX')

    # Testing write(addr, bytes)
    val = bytes('Z' * 8, 'utf8')
    pwndbg.memory.write(stack_addr, val)
    assert pwndbg.memory.read(stack_addr, len(val)+4) == bytearray('Z'*8 + 'YYXX', 'utf8')

