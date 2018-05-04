from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import tests
from pwndbg.commands.nearpc import emulate, nearpc, pdisass
from pwndbg.commands.windbg import u

EMULATE_DISASM_BINARY = tests.binaries.get('emulate_disasm.out')


def test_disasm_commands(start_binary):
    """
    Tests emulate command and its caching behavior
    """
    start_binary(EMULATE_DISASM_BINARY)

    assert emulate(to_string=True) == [
        ' ► 0x400080 <_start>    jmp    label                         <0x400083>',
        '    ↓', '   0x400083 <label>     nop    ',
        '   0x400084             add    byte ptr [rax], al',
        '   0x400086             add    byte ptr [rax], al',
        '   0x400088             add    byte ptr [rax], al',
        '   0x40008a             add    byte ptr [rax], al',
        '   0x40008c             add    byte ptr [rax], al',
        '   0x40008e             add    byte ptr [rax], al',
        '   0x400090             add    byte ptr [rax], al',
        '   0x400092             add    byte ptr [rax], al',
        '   0x400094             add    byte ptr [rax], al'
    ]

    disasm_without_emu = [
        ' ► 0x400080 <_start>      jmp    label                         <0x400083>',
        ' ',
        '   0x400082 <_start+2>    nop    ',
        '   0x400083 <label>       nop    ',
        '   0x400084               add    byte ptr [rax], al', '   0x400086               add    byte ptr [rax], al',
        '   0x400088               add    byte ptr [rax], al', '   0x40008a               add    byte ptr [rax], al',
        '   0x40008c               add    byte ptr [rax], al', '   0x40008e               add    byte ptr [rax], al',
        '   0x400090               add    byte ptr [rax], al', '   0x400092               add    byte ptr [rax], al'
    ]

    assert nearpc(to_string=True) == disasm_without_emu
    assert emulate(to_string=True, emulate=False) == disasm_without_emu
    assert pdisass(to_string=True) == disasm_without_emu
    assert u(to_string=True) == disasm_without_emu
