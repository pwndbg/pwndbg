from __future__ import annotations

import os
import shutil
import tempfile

import gdb
import pytest

import pwndbg.libc
import pwndbg.libc.glibc

from . import get_binary

# We used the same binary as heap tests since it will use libc, and many functions are mainly for debugging the heap
HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.native.out")


@pytest.mark.parametrize(
    "have_debugging_information", [True, False], ids=["does-not-have-(*)", "have-(*)"]
)
def test_finding_glibc_filepath(start_binary, have_debugging_information):
    # Check if we can find the libc if nothing special happens
    if not have_debugging_information:
        # Make sure the (*) in the output of `info sharedlibrary` won't affect the result
        gdb.execute("set debug-file-directory")
        gdb.execute("set debuginfod enabled off")

    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")
    if not have_debugging_information:
        assert "(*)" in gdb.execute("info sharedlibrary", to_string=True)

    libc_path = pwndbg.libc.filepath()
    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
    assert libc_path is not None

    # Create 3 copies of the libc with the filenames: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
    # Note: The version in the above filename doesn't matter, just some tests for the common libc names we might use with LD_PRELOAD
    test_libc_names = ["libc-2.36.so", "libc6_2.36-0ubuntu4_amd64.so", "libc.so"]
    with tempfile.TemporaryDirectory() as tmp_dir:
        for test_libc_name in test_libc_names:
            test_libc_path = os.path.join(tmp_dir, test_libc_name)
            shutil.copy(libc_path, test_libc_path)
            gdb.execute(f"set environment LD_PRELOAD={test_libc_path}")
            start_binary(HEAP_MALLOC_CHUNK)
            gdb.execute("break break_here")
            gdb.execute("continue")
            # Check if we can find the libc loaded by LD_PRELOAD
            if not have_debugging_information:
                assert "(*)" in gdb.execute("info sharedlibrary", to_string=True)
            assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
            assert str(pwndbg.libc.filepath()) == test_libc_path

        # Unfortunatly, if we used LD_PRELOAD to load libc, we might cannot find the libc's filename
        # In this case, the "unknown" libc implementation will be returned and the ld mapping will
        # be returned instead of the libc one.
        test_libc_path = os.path.join(tmp_dir, "a_weird_name_that_does_not_look_like_a_1ibc.so")
        shutil.copy(libc_path, test_libc_path)
        gdb.execute(f"set environment LD_PRELOAD={test_libc_path}")
        start_binary(HEAP_MALLOC_CHUNK)
        gdb.execute("break break_here")
        gdb.execute("continue")

        assert pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN
        assert pwndbg.libc.filepath().name == "ld-linux-x86-64.so.2"


def test_set_glibc_version(start_binary):
    # Needed for glibc.version() as it requires an alive process.
    start_binary(HEAP_MALLOC_CHUNK)

    # Make sure glibc is loaded.
    gdb.execute("break main")
    gdb.execute("continue")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC

    errmsg = "Invalid GLIBC version:"
    err = gdb.execute("set glibc 2.31a", to_string=True)
    assert err.startswith(errmsg)

    err = gdb.execute("set glibc 2.31", to_string=True)
    assert err == ""
    assert pwndbg.libc.version() == (2, 31)

    err = gdb.execute("set glibc 2.34", to_string=True)
    assert err == ""
    assert pwndbg.libc.version() == (2, 34)
