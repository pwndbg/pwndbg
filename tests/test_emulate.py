
import tests
from pwndbg.commands.nearpc import emulate
from pwndbg.commands.nearpc import nearpc
from pwndbg.commands.nearpc import pdisass
from pwndbg.commands.windbg import u

EMULATE_DISASM_BINARY = tests.binaries.get('emulate_disasm.out')
EMULATE_DISASM_LOOP_BINARY = tests.binaries.get('emulate_disasm_loop.out')


def test_emulate_disasm(start_binary):
    """
    Tests emulate command and its caching behavior
    """
    start_binary(EMULATE_DISASM_BINARY)

    assert emulate(to_string=True) == [
        ' ► 0x401000 <_start>    jmp    label                      <label>',
        '    ↓',
        '   0x401003 <label>     nop    ',
        '   0x401004             add    byte ptr [rax], al',
        '   0x401006             add    byte ptr [rax], al',
        '   0x401008             add    byte ptr [rax], al',
        '   0x40100a             add    byte ptr [rax], al',
        '   0x40100c             add    byte ptr [rax], al',
        '   0x40100e             add    byte ptr [rax], al',
        '   0x401010             add    byte ptr [rax], al',
        '   0x401012             add    byte ptr [rax], al',
        '   0x401014             add    byte ptr [rax], al'
    ]

    disasm_without_emu = [
        ' ► 0x401000 <_start>      jmp    label                      <label>',
        ' ',
        '   0x401002 <_start+2>    nop    ',
        '   0x401003 <label>       nop    ',
        '   0x401004               add    byte ptr [rax], al',
        '   0x401006               add    byte ptr [rax], al',
        '   0x401008               add    byte ptr [rax], al',
        '   0x40100a               add    byte ptr [rax], al',
        '   0x40100c               add    byte ptr [rax], al',
        '   0x40100e               add    byte ptr [rax], al',
        '   0x401010               add    byte ptr [rax], al',
        '   0x401012               add    byte ptr [rax], al'
    ]

    assert nearpc(to_string=True) == disasm_without_emu
    assert emulate(to_string=True, emulate=False) == disasm_without_emu
    assert pdisass(to_string=True) == disasm_without_emu
    assert u(to_string=True) == disasm_without_emu


def test_emulate_disasm_loop(start_binary):
    start_binary(EMULATE_DISASM_LOOP_BINARY)

    assert emulate(to_string=True) == [
        ' ► 0x401000 <_start>       movabs rsi, string                   <0x401014>',
        '   0x40100a <_start+10>    mov    rdi, rsp',
        '   0x40100d <_start+13>    mov    ecx, 3',
        '   0x401012 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
        '    ↓',
        '   0x401012 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
        '    ↓',
        '   0x401012 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
        '    ↓',
        '   0x401012 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
        '   0x401014 <string>       xor    dword ptr [rdx], esi',
        '   0x401016 <string+2>     xor    esi, dword ptr [rsi]',
        '   0x40101d                add    byte ptr [rax], al',
        '   0x40101f                add    byte ptr [rax], al',
    ]

    disasm_without_emu = [
        ' ► 0x401000 <_start>       movabs rsi, string                   <0x401014>',
        '   0x40100a <_start+10>    mov    rdi, rsp',
        '   0x40100d <_start+13>    mov    ecx, 3',
        '   0x401012 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
        '   0x401014 <string>       xor    dword ptr [rdx], esi',
        '   0x401016 <string+2>     xor    esi, dword ptr [rsi]',
        '   0x40101d                add    byte ptr [rax], al',
        '   0x40101f                add    byte ptr [rax], al',
        '   0x401021                add    byte ptr [rax], al',
        '   0x401023                add    byte ptr [rax], al',
        '   0x401025                add    byte ptr [rax], al',
    ]

    assert nearpc(to_string=True) == disasm_without_emu
    assert emulate(to_string=True, emulate=False) == disasm_without_emu
    assert pdisass(to_string=True) == disasm_without_emu
    assert u(to_string=True) == disasm_without_emu
