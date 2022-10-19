import os
import sys

import pwndbg.commands.cymbol
import pwndbg.gdblib.dt
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_cymbol(start_binary):
    start_binary(REFERENCE_BINARY)

    pwndbg_cachedir = pwndbg.lib.tempfile.cachedir("custom-symbols")
    custom_structure_example = """
        typedef struct example_struct {
            int a;
            char b[16];
            char* c;
            void* d;
        } example_t;
    """
    custom_structure_example_path = os.path.join(pwndbg_cachedir, "example.c")
    with open(custom_structure_example_path, "w") as f:
        f.write(custom_structure_example)

    # Test whether OnlyWhenStructureExists decorator works properly
    assert pwndbg.commands.cymbol.OnlyWhenStructureExists(lambda x, y: True)("dummy") is None
    assert pwndbg.commands.cymbol.OnlyWhenStructureExists(lambda x, y: True)("example") is True

    # Test whether PromptForOverwrite decorator works properly
    # Returns True when the custom structure 'dummy' does not exist and there is no need for an overwrite prompt.
    assert pwndbg.commands.cymbol.PromptForOverwrite(lambda x: True)("dummy") is True

    # Test whether generate_debug_symbols() works properly
    assert pwndbg.commands.cymbol.generate_debug_symbols(custom_structure_example_path) is not None

    # Test whether load_custom_structure() works properly
    pwndbg.commands.cymbol.load_custom_structure("example")
    # Not much but honest work.
    assert "+0x0004 b" in pwndbg.gdblib.dt.dt("example_t").strip()

    # Test whether add_custom_structure() works properly.
    saved_read = sys.stdin.read
    saved_exists = os.path.exists
    # We do a little hack here :)
    sys.stdin.read = (
        lambda: """
        typedef struct example_struct2 {
            long a;
            int b[16];
            int** c;
            void* d;
        } example2_t;
    """
    )
    # Always overwrite files which exist.
    os.path.exists = lambda x: False
    pwndbg.commands.cymbol.add_custom_structure("example2")
    # Not much but honest work.
    assert ": int [16]" in pwndbg.gdblib.dt.dt("example2_t").strip()

    # Restore
    sys.stdin.read = saved_read
    os.path.exists = saved_exists
