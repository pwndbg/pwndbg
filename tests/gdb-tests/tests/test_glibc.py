from __future__ import annotations

import os
import shutil
import tempfile

import gdb
import pytest

import pwndbg.glibc
import tests

# We used the same binary as heap tests since it will use libc, and many functions are mainly for debugging the heap
HEAP_MALLOC_CHUNK = tests.binaries.get("heap_malloc_chunk.out")


@pytest.mark.parametrize(
    "have_debugging_information", [True, False], ids=["does-not-have-(*)", "have-(*)"]
)
def test_parsing_info_sharedlibrary_to_find_libc_filename(start_binary, have_debugging_information):
    # Check if we can find the libc if nothing special happens
    if not have_debugging_information:
        # Make sure the (*) in the output of `info sharedlibrary` won't affect the result
        gdb.execute("set debug-file-directory")
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")
    if not have_debugging_information:
        assert "(*)" in gdb.execute("info sharedlibrary", to_string=True)
    libc_path = pwndbg.glibc.get_libc_filename_from_info_sharedlibrary()
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
            assert pwndbg.glibc.get_libc_filename_from_info_sharedlibrary() == test_libc_path

        # Unfortunatly, if we used LD_PRELOAD to load libc, we might cannot find the libc's filename
        # In this case, the function should return None instead of crashing
        test_libc_path = os.path.join(tmp_dir, "a_weird_name_that_does_not_look_like_a_1ibc.so")
        shutil.copy(libc_path, test_libc_path)
        gdb.execute(f"set environment LD_PRELOAD={test_libc_path}")
        start_binary(HEAP_MALLOC_CHUNK)
        gdb.execute("break break_here")
        gdb.execute("continue")
        assert pwndbg.glibc.get_libc_filename_from_info_sharedlibrary() is None


def test_set_glibc_version(start_binary):
    # Needed for glibc.get_version() as it has @OnlyWhenRunning
    start_binary(HEAP_MALLOC_CHUNK)

    errmsg = "Invalid GLIBC version:"
    err = gdb.execute("set glibc 2.31a", to_string=True)
    assert err.startswith(errmsg)

    err = gdb.execute("set glibc 2.31", to_string=True)
    assert err == ""
    assert pwndbg.glibc.get_version() == (2, 31)

    err = gdb.execute("set glibc 2.34", to_string=True)
    assert err == ""
    assert pwndbg.glibc.get_version() == (2, 34)
