from __future__ import annotations

import gdb
import pytest

import pwndbg.aglib.memory
import pwndbg.aglib.regs

from . import get_binary

CANARY_X86_64_BINARY = get_binary("canary.x86-64.out")
CANARY_I386_BINARY = get_binary("canary.i386.out")


@pytest.mark.integration
@pytest.mark.parametrize(
    "binary, reg_name",
    [
        (CANARY_X86_64_BINARY, "rax"),
        (CANARY_I386_BINARY, "eax"),
    ],
    ids=["x86-64", "i386"],
)
def test_command_canary(start_binary, binary, reg_name):
    """
    Tests the canary command for x86-64 and i386 architectures
    """
    start_binary(binary)

    gdb.execute("break main")
    gdb.execute("run")
    gdb.execute("stepi")

    register = getattr(pwndbg.aglib.regs, reg_name)
    canary_value, at_random = pwndbg.commands.canary.canary_value()

    raw = pwndbg.aglib.memory.read_pointer_width(at_random)
    mask = pwndbg.aglib.arch.ptrmask ^ 0xFF
    masked_raw = raw & mask

    tls_addr = pwndbg.commands.canary.find_tls_canary_addr()
    raw_tls = pwndbg.aglib.memory.read_pointer_width(tls_addr) & mask

    # Check AT_RANDOM
    assert masked_raw == canary_value
    # Check TLS Canary
    assert raw_tls == canary_value
    # Check Canary
    assert register == canary_value
