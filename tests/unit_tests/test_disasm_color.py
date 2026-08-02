from __future__ import annotations

from unittest.mock import MagicMock

import pwndbg

# Setup mocks required for pwndbg import
from tests.unit_tests.mocks import dbg_mod
from tests.unit_tests.mocks import gdb  # noqa: F401
from tests.unit_tests.mocks import gdblib  # noqa: F401

dbg_mod.dbg.is_gdblib_available = lambda: False
dbg_mod.dbg.event_handler = lambda *a, **kw: lambda f: f
dbg_mod.dbg.commands = list
dbg_mod.dbg.add_command = lambda *a, **kw: None
pwndbg.dbg = dbg_mod.dbg

from capstone6pwndbg import CS_OP_IMM

from pwndbg.color import disasm

if not hasattr(pwndbg.aglib, "regs") or pwndbg.aglib.regs is None:
    pwndbg.aglib.regs = MagicMock(pc=0)

if not hasattr(pwndbg.aglib, "arch") or pwndbg.aglib.arch is None:
    pwndbg.aglib.arch = MagicMock(name="x86-64")


# ==============================================================================
# Tests for decode_ascii_immediate(val)
# ==============================================================================


def test_decode_immediate_string_utf8_and_ascii():
    """Test decoding of valid ASCII and UTF-8 multibyte (Russian/Cyrillic) immediates."""
    # 8-byte ASCII: "/bin//sh" -> 0x68732f2f6e69622f
    assert disasm.decode_immediate_string(0x68732F2F6E69622F) == '"/bin//sh"'

    # 6-byte UTF-8 Russian string: "мяу\n" -> 0x0A83D18FD1BCD0
    assert disasm.decode_immediate_string(0x0A83D18FD1BCD0) == '"мяу\\n"'

    # 4-byte ASCII: "test" -> 0x74736574
    assert disasm.decode_immediate_string(0x74736574) == '"test"'


def test_decode_immediate_string_negative_and_zero():
    """Test behavior with zero and negative numbers."""
    assert disasm.decode_immediate_string(0) is None
    assert disasm.decode_immediate_string(-1) is None
    assert disasm.decode_immediate_string(-0x10) is None
    assert disasm.decode_immediate_string(-0x7FFFFFFFFFFFFFFF) is None


def test_decode_immediate_string_corrupted_and_unprintable():
    """Test behavior with unprintable bytes, whitespace-only, and special control chars."""
    # Non-printable byte (0x01020304)
    assert disasm.decode_immediate_string(0x01020304) is None

    # Spaces only (0x20202020 -> "    "), strip() makes it empty -> returns None
    assert disasm.decode_immediate_string(0x20202020) is None

    # Control chars \n, \r, \t with printable char 'A' -> 0x0a0d0941 ("A\t\r\n")
    assert disasm.decode_immediate_string(0x0A0D0941) == '"A\\t\\r\\n"'


# ==============================================================================
# Tests for enrich_instruction_annotation(ins)
# ==============================================================================


class DummyOperand:
    def __init__(
        self, op_type=None, imm=None, before_value_resolved=None, before_value=None, str_val=None
    ):
        if op_type is not None:
            self.type = op_type
        if imm is not None:
            self.imm = imm
        if before_value_resolved is not None:
            self.before_value_resolved = before_value_resolved
        if before_value is not None:
            self.before_value = before_value
        if str_val is not None:
            self.str = str_val


class DummyInstruction:
    def __init__(self, mnemonic="", op_str="", operands=None, target=None, annotation=None):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = operands or []
        self.target = target
        self.annotation = annotation


def test_enrich_annotation_utf8_immediate():
    """Test that UTF-8 multibyte strings like 'мяу\\n' are correctly annotated."""
    ins = DummyInstruction(
        mnemonic="movabs",
        operands=[
            DummyOperand(str_val="rax"),
            DummyOperand(op_type=CS_OP_IMM, imm=0x0A83D18FD1BCD0),
        ],
    )
    disasm.enrich_instruction_annotation(ins)  # type: ignore[arg-type]
    assert ins.annotation is not None and '"мяу\\n"' in ins.annotation


def test_enrich_annotation_negative_immediates():
    """Test that negative immediate operands do not cause errors or invalid ASCII decodings."""
    ins = DummyInstruction(mnemonic="mov", operands=[DummyOperand(op_type=CS_OP_IMM, imm=-1)])
    disasm.enrich_instruction_annotation(ins)  # type: ignore[arg-type]
    assert ins.annotation is None


def test_enrich_annotation_syscall_decoding():
    """Test syscall decoding for x86-64 architecture."""
    pwndbg.aglib.arch.name = "x86-64"

    # Valid syscall: sys_execve (59 on x86-64)
    ins_execve = DummyInstruction(
        mnemonic="mov",
        operands=[DummyOperand(str_val="rax"), DummyOperand(op_type=CS_OP_IMM, imm=59)],
    )
    disasm.enrich_instruction_annotation(ins_execve)  # type: ignore[arg-type]
    assert ins_execve.annotation is not None and "sys_execve" in ins_execve.annotation


def test_enrich_annotation_file_descriptors():
    """Test file descriptor detection (stdin=0, stdout=1, stderr=2)."""
    for fd, expected in [(0, "stdin"), (1, "stdout"), (2, "stderr")]:
        ins = DummyInstruction(
            mnemonic="mov",
            operands=[DummyOperand(str_val="rdi"), DummyOperand(op_type=CS_OP_IMM, imm=fd)],
        )
        disasm.enrich_instruction_annotation(ins)  # type: ignore[arg-type]
        assert ins.annotation is not None and expected in ins.annotation


def test_enrich_annotation_memory_addresses(monkeypatch):
    """Test memory string dereferencing with zero, negative, and valid addresses."""

    def mock_is_readable_address(addr):
        if addr in (0x1000, -0x1000):
            return True
        return False

    def mock_memory_string(addr, max=32):
        if addr == 0x1000:
            return bytearray(b"hello_world")
        if addr == -0x1000:
            raise MemoryError("Cannot read negative memory address")
        return bytearray()

    monkeypatch.setattr(pwndbg.aglib.memory, "is_readable_address", mock_is_readable_address)
    monkeypatch.setattr(pwndbg.aglib.memory, "string", mock_memory_string)

    # 1. Zero address ins.target = 0
    ins_zero = DummyInstruction(target=0)
    disasm.enrich_instruction_annotation(ins_zero)  # type: ignore[arg-type]
    assert ins_zero.annotation is None

    # 2. Negative address ins.target = -0x1000 (should safely catch MemoryError without crashing)
    ins_neg = DummyInstruction(target=-0x1000)
    disasm.enrich_instruction_annotation(ins_neg)  # type: ignore[arg-type]
    assert ins_neg.annotation is None

    # 3. Valid address returning bytearray
    ins_valid_str = DummyInstruction(target=0x1000)
    disasm.enrich_instruction_annotation(ins_valid_str)  # type: ignore[arg-type]
    assert ins_valid_str.annotation is not None and '-> "hello_world"' in ins_valid_str.annotation


def test_instructions_and_padding_syscall_name_none():
    """Test edge case where ins.syscall is set but ins.syscall_name is None (safely handled)."""
    ins = MagicMock()
    ins.syscall = 59
    ins.syscall_name = None
    ins.has_jump_target = False
    ins.target = None
    ins.annotation = None
    ins.annotation_padding = None
    ins.mnemonic = "syscall"
    ins.asm_string = "syscall"
    ins.address = 0x1000
    ins.groups = set()
    ins.condition = None
    ins.is_conditional_jump_taken = False
    ins.operands = []

    # Should safely process without raising TypeError
    res = disasm.instructions_and_padding([ins], linear=False)
    assert len(res) == 1
