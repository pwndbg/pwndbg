from __future__ import annotations

from unittest.mock import patch

import gdb
import pytest

import pwndbg.glibc
import tests

X86_64_BINARY = tests.binaries.get("onegadget.x86-64.out")
I386_BINARY = tests.binaries.get("onegadget.i386.out")

X86_64_ONEGADGET_OUTPUT = """\
0x80bd0 posix_spawn(rbx+0xe0, "/bin/sh", rdx, rbp, rsp+0x60, environ)
constraints:
  address rsp+0x78 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, (u64)(xmm0 >> 64), [rsp+0x70], NULL} is a valid argv
  rbx+0xe0 == NULL || writable: rbx+0xe0
  rdx == NULL || (s32)[rdx+0x4] <= 0
  rbp == NULL || (u16)[rbp] == NULL

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
"""

I386_ONEGADGET_OUTPUT = """\
0xdeee3 execve("/bin/sh", [ebp-0x30], [ebp-0x2c])
constraints:
  address ebp-0x20 is writable
  ebx is the GOT address of libc
  [[ebp-0x30]] == NULL || [ebp-0x30] == NULL || [ebp-0x30] is a valid argv
  [[ebp-0x2c]] == NULL || [ebp-0x2c] == NULL || [ebp-0x2c] is a valid envp

0x172951 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL
"""


@patch("shutil.which", return_value="one_gadget")
@patch("subprocess.check_output", return_value=X86_64_ONEGADGET_OUTPUT)
def test_find_x86_64_onegadget(check_output, which):
    gdb.execute(f"file {X86_64_BINARY}")
    gdb.execute("break break_here")
    gdb.execute("run")

    # TODO: Find a proper way to test every possible constraint
    # TODO: Check correctness of the verbose output

    # Make all gadgets unsatisfiable
    gdb.execute("set $saved_rbp=$rbp")
    gdb.execute("set $xmm0.uint128=0xdeadbeafdeadbeaf")
    gdb.execute("set $rcx=$rbx=$rdx=$rbp=$rsi=0xdeadbeef")

    output = gdb.execute("onegadget --verbose", to_string=True)

    # No gadgets should be found
    assert "Found 0 SAT gadgets" in output
    assert "Found 2 UNSAT gadgets" in output
    assert "Found 0 UNKNOWN gadgets" in output
    assert "0x80bd0" not in output
    assert "0xebc88" not in output

    # Should show unsatisfiable gadgets
    output = gdb.execute("onegadget --show-unsat --verbose", to_string=True)
    assert "0x80bd0" in output
    assert "0xebc88" in output

    # Make 0xebc88 satisfiable
    gdb.execute("set $rbp=$saved_rbp")
    gdb.execute("set $rsi=$rdx=0")

    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0xebc88" in output

    # Check if rsi is a valid argv
    gdb.execute("set $rsi=argv")
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0xebc88" in output

    # Check if rdx is a valid envp
    gdb.execute("set $rdx=envp")
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0xebc88" in output

    # Make 0x80bd0 satisfiable and 0xebc88 unsatisfiable
    gdb.execute("set $rcx=0")
    gdb.execute("set *(unsigned long*)($rsp+0x70)=0")
    gdb.execute("set $rbx=buf+0x500")
    gdb.execute("set $rdx=buf+0x500")
    gdb.execute("set $rbp=0")

    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0x80bd0" in output

    # Check if rcx is readable, (u64)(xmm0 >> 64) is NULL
    gdb.execute("set $rcx=buf+0x500")
    gdb.execute("set $xmm0.uint128=0x0")
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0x80bd0" in output

    # Check if rcx is readable, (u64)(xmm0 >> 64) is readable, [rsp+0x70] is readable
    gdb.execute("set $xmm0.v2_int64[1]=buf+0x500")
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 0 SAT gadgets" in output
    assert "Found 1 UNKNOWN gadgets" in output
    assert "0x80bd0" in output

    # Should exclude unknown gadgets
    output = gdb.execute("onegadget --no-unknown --verbose", to_string=True)
    assert "0x80bd0" not in output

    # Make 0x80bd0 satisfiable again
    gdb.execute("set $rcx=0")

    # Check if (s32)[rdx+0x4] <= 0
    gdb.execute("set *(int*)($rdx+0x4)=-1")
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0x80bd0" in output


@patch("shutil.which", return_value="one_gadget")
@patch("subprocess.check_output", return_value=I386_ONEGADGET_OUTPUT)
def test_find_i386_onegadget(check_output, which):
    gdb.execute(f"file {I386_BINARY}")
    gdb.execute("break break_here")
    try:
        gdb.execute("run")
    except gdb.error:
        pytest.skip("Test not supported on this platform.")

    # TODO: Find a proper way to test every possible constraint
    # TODO: Check correctness of the verbose output

    # Make all gadgets unsatisfiable
    gdb.execute("set $ebx=$esi=$eax=0xdeadbeaf")
    gdb.execute("set $saved_ebp=$ebp")
    gdb.execute("set $ebp=0xdeadbeaf")

    # Run onegadget
    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 0 SAT gadgets" in output
    assert "Found 2 UNSAT gadgets" in output
    assert "Found 0 UNKNOWN gadgets" in output
    assert "0xdeee3" not in output
    assert "0x172951" not in output

    # Should show unsatisfiable gadgets
    output = gdb.execute("onegadget --show-unsat --verbose", to_string=True)
    assert "0xdeee3" in output
    assert "0x172951" in output

    # Make 0x172951 satisfiable
    glibc_got_plt = pwndbg.glibc.get_section_address_by_name(".got.plt")
    gdb.execute(f"set $esi={glibc_got_plt}")
    gdb.execute("set $eax=0")

    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0x172951" in output

    # Make 0x172951 unsatisfiable again
    gdb.execute("set $esi=$eax=0xdeadbeaf")

    # Make 0xdeee3 satisfiable
    gdb.execute(f"set $ebx={glibc_got_plt}")
    gdb.execute("set $ebp=$saved_ebp")
    gdb.execute("set *(void**)($ebp-0x30)=0")
    gdb.execute("set *(void**)($ebp-0x2c)=envp")

    output = gdb.execute("onegadget --verbose", to_string=True)
    assert "Found 1 SAT gadgets" in output
    assert "0xdeee3" in output


@patch("shutil.which", return_value="one_gadget")
def test_onegadget_cache(which):
    gdb.execute(f"file {X86_64_BINARY}")
    gdb.execute("break break_here")
    gdb.execute("run")

    # Run onegadget with mock output
    with patch("subprocess.check_output", return_value=X86_64_ONEGADGET_OUTPUT):
        output = gdb.execute("onegadget --show-unsat --verbose", to_string=True)

    # Run onegadget again to ensure we're using the cache
    with patch("subprocess.check_output", side_effect=AssertionError("Cache miss")):
        assert output == gdb.execute("onegadget --show-unsat --verbose", to_string=True)


@patch("shutil.which", return_value=None)
def test_no_onegadget_installed(which):
    gdb.execute(f"file {X86_64_BINARY}")
    gdb.execute("break break_here")
    gdb.execute("run")
    # pwndbg should not be able to find onegadget
    output = gdb.execute("onegadget", to_string=True)

    assert output == "Could not find one_gadget. Please ensure it's installed and in $PATH.\n"


@patch("shutil.which", return_value="one_gadget")
def test_no_libc_loaded_for_onegadget(which):
    gdb.execute(f"file {X86_64_BINARY}")
    gdb.execute("starti")
    # Since we don't have a libc loaded, we should get an error message
    output = gdb.execute("onegadget", to_string=True)

    assert output == "Could not find libc. Please ensure it's loaded.\n"
