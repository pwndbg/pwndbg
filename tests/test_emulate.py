"""
Tests emulate command and its caching behavior
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pytest
import tests
from pwndbg.commands.nearpc import emulate
from pwndbg.commands.nearpc import nearpc
from pwndbg.commands.nearpc import pdisass
from pwndbg.commands.windbg import u


BIN_UNCONDITIONAL_JUMP = tests.binaries.emulation.get('unconditional_jump.out')
BIN_REP_MOVSB = tests.binaries.emulation.get('rep_movsb.out')
BIN_CALL = tests.binaries.emulation.get('call.out')
BIN_INFINITE_LOOP = tests.binaries.emulation.get('infinite_loop.out')
BIN_BRANCH_TAKEN = tests.binaries.emulation.get('branch_taken.out')
BIN_BRANCH_NOT_TAKEN = tests.binaries.emulation.get('branch_not_taken.out')
BIN_MULTIPLE_BRANCH_TAKEN = tests.binaries.emulation.get('multiple_branch_taken.out')


@pytest.fixture
def assert_binary_emulations(start_binary):
    def _assert_binary_emulations(binary_path, expected_emu, expected_dis):
        start_binary(binary_path)

        assert emulate(to_string=True) == expected_emu

        assert nearpc(to_string=True) == expected_dis
        assert emulate(to_string=True, emulate=False) == expected_dis
        assert pdisass(to_string=True) == expected_dis
        assert u(to_string=True) == expected_dis

    return _assert_binary_emulations


def test_disasm_commands_unconditional_jump(assert_binary_emulations):
    assert_binary_emulations(
        binary_path=BIN_UNCONDITIONAL_JUMP,
        expected_emu=[
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
        ],
        expected_dis=[
            ' ► 0x400080 <_start>      jmp    label                         <0x400083>',
            ' ',
            '   0x400082 <_start+2>    nop    ',
            '   0x400083 <label>       nop    ',
            '   0x400084               add    byte ptr [rax], al',
            '   0x400086               add    byte ptr [rax], al',
            '   0x400088               add    byte ptr [rax], al',
            '   0x40008a               add    byte ptr [rax], al',
            '   0x40008c               add    byte ptr [rax], al',
            '   0x40008e               add    byte ptr [rax], al',
            '   0x400090               add    byte ptr [rax], al', '   0x400092               add    byte ptr [rax], al'
        ]
    )


def test_disasm_commands_branch_taken(assert_binary_emulations):
    assert_binary_emulations(
        BIN_BRANCH_TAKEN,
        expected_emu=[
            ' ► 0x400080 <_start>      test   rax, rax',
            '   0x400083 <_start+3>    je     branch                        <0x40008a>',
            '    ↓',
            '   0x40008a <branch>      nop    ',
            '   0x40008b               add    byte ptr [rax], al',
            '   0x40008d               add    byte ptr [rax], al',
            '   0x40008f               add    byte ptr [rax], al',
            '   0x400091               add    byte ptr [rax], al',
            '   0x400093               add    byte ptr [rax], al',
            '   0x400095               add    byte ptr [rax], al',
            '   0x400097               add    byte ptr [rax], al',
            '   0x400099               add    byte ptr [rax], al'
        ],
        expected_dis=[
            ' ► 0x400080 <_start>      test   rax, rax',
            '   0x400083 <_start+3>    je     branch                        <0x40008a>',
            ' ',
            '   0x400085 <_start+5>    mov    eax, 0x1337',
            '   0x40008a <branch>      nop    ',
            '   0x40008b               add    byte ptr [rax], al',
            '   0x40008d               add    byte ptr [rax], al',
            '   0x40008f               add    byte ptr [rax], al',
            '   0x400091               add    byte ptr [rax], al',
            '   0x400093               add    byte ptr [rax], al',
            '   0x400095               add    byte ptr [rax], al',
            '   0x400097               add    byte ptr [rax], al'
        ]
    )


def test_disasm_commands_branch_not_taken(assert_binary_emulations):
    assert_binary_emulations(
        BIN_BRANCH_NOT_TAKEN,
        expected_emu=[
            ' ► 0x400080 <_start>      test   rax, rax',
            '   0x400083 <_start+3>    jne    branch                        <0x40008a>',
            ' ',
            '   0x400085 <_start+5>    mov    eax, 0x1337',
            '   0x40008a <branch>      nop    ',
            '   0x40008b               add    byte ptr [rax], al',
            '   0x40008d               add    byte ptr [rax], al',
            '   0x40008f               add    byte ptr [rax], al',
            '   0x400091               add    byte ptr [rax], al',
            '   0x400093               add    byte ptr [rax], al',
            '   0x400095               add    byte ptr [rax], al',
            '   0x400097               add    byte ptr [rax], al'
        ],
        expected_dis=[
            ' ► 0x400080 <_start>      test   rax, rax',
            '   0x400083 <_start+3>    jne    branch                        <0x40008a>',
            ' ',
            '   0x400085 <_start+5>    mov    eax, 0x1337',
            '   0x40008a <branch>      nop    ',
            '   0x40008b               add    byte ptr [rax], al',
            '   0x40008d               add    byte ptr [rax], al',
            '   0x40008f               add    byte ptr [rax], al',
            '   0x400091               add    byte ptr [rax], al',
            '   0x400093               add    byte ptr [rax], al',
            '   0x400095               add    byte ptr [rax], al',
            '   0x400097               add    byte ptr [rax], al'
        ]
    )


def test_disasm_commands_multiple_branch_taken(assert_binary_emulations):
    dis = [
        ' ► 0x400080 <_start>      test   rax, rax',
        '   0x400083 <_start+3>    je     _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>      test   rax, rax',
        '   0x400083 <_start+3>    je     _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>      test   rax, rax',
        '   0x400083 <_start+3>    je     _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>      test   rax, rax',
        '   0x400083 <_start+3>    je     _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>      test   rax, rax',
        '   0x400083 <_start+3>    je     _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>      test   rax, rax'
    ]

    assert_binary_emulations(BIN_MULTIPLE_BRANCH_TAKEN, expected_emu=dis, expected_dis=dis)


def test_disasm_commands_call_instruction(assert_binary_emulations):
    # The emulation stops at call instruction so nothing after it is emulated.
    dis = [
        ' ► 0x400080 <_start>         mov    eax, 0x1337',
        '   0x400085 <_start+5>       mov    ebx, 0xffff',
        '   0x40008a <_start+10>      call   some_func                     <0x400092>',
        ' ',
        '   0x40008f <_start+15>      nop    ',
        '   0x400090 <_start+16>      call   rax',
        ' ',
        '   0x400092 <some_func>      mov    rax, rbx',
        '   0x400095 <some_func+3>    ret    ',
        ' ',
        '   0x400096                  add    byte ptr [rax], al',
        '   0x400098                  add    byte ptr [rax], al',
        '   0x40009a                  add    byte ptr [rax], al',
        '   0x40009c                  add    byte ptr [rax], al'
    ]

    assert_binary_emulations(binary_path=BIN_CALL, expected_emu=dis, expected_dis=dis)


def test_disasm_commands_infinite_loop(assert_binary_emulations):
    dis = [
        ' ► 0x400080 <_start>    jmp    _start                        <0x400080>',
        '    ↓',
        ' ► 0x400080 <_start>    jmp    _start                        <0x400080>'
    ]

    assert_binary_emulations(BIN_INFINITE_LOOP, expected_emu=dis, expected_dis=dis)


def test_disasm_commands_rep_movsb(assert_binary_emulations):
    assert_binary_emulations(
        binary_path=BIN_REP_MOVSB,
        expected_emu=[
            ' ► 0x400080 <_start>       movabs rsi, string                   <0x400094>',
            '   0x40008a <_start+10>    mov    rdi, rsp',
            '   0x40008d <_start+13>    mov    ecx, 3',
            '   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
            '    ↓',
            '   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
            '    ↓',
            '   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
            '    ↓',
            '   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
            '   0x400094 <string>       xor    dword ptr [rdx], esi',
            '   0x400096 <string+2>     xor    esi, dword ptr [rsi]',
            '   0x40009d                add    byte ptr [rax], al',
            '   0x40009f                add    byte ptr [rax], al'
        ],
        expected_dis=[
            ' ► 0x400080 <_start>       movabs rsi, string                   <0x400094>',
            '   0x40008a <_start+10>    mov    rdi, rsp',
            '   0x40008d <_start+13>    mov    ecx, 3',
            '   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]',
            '   0x400094 <string>       xor    dword ptr [rdx], esi',
            '   0x400096 <string+2>     xor    esi, dword ptr [rsi]',
            '   0x40009d                add    byte ptr [rax], al',
            '   0x40009f                add    byte ptr [rax], al',
            '   0x4000a1                add    byte ptr [rax], al',
            '   0x4000a3                add    byte ptr [rax], al',
            '   0x4000a5                add    byte ptr [rax], al'
        ]
    )
