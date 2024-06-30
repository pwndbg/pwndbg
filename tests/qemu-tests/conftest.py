"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

from pwn import *
import gdb
import pytest
import random

_start_binary_called = False



@pytest.fixture
def compile_and_run():
    """
    Returns function that launches given binary with 'starti' command
    
    The `path` is returned from `make_elf_from_assembly` (provided by pwntools)
    """


    qemu: subprocess.Popen = None
    binary_tmp_path: bytes = None

    def _start_binary(asm: str, arch: str, *args):
        nonlocal qemu
        nonlocal binary_tmp_path

        port = os.environ.get("QEMU_PORT")
        context.arch = arch
        binary_tmp_path = make_elf_from_assembly(asm)


        qemu = subprocess.Popen([
            f"qemu-{arch}",
            f"-g",
            f"{port}",
            f"{binary_tmp_path}",
        ])

        gdb.execute("target remote :1234")
        gdb.execute("set exception-verbose on")

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary

    os.remove(binary_tmp_path)

    qemu.terminate()

    

    # Ensure qemu is stopped
