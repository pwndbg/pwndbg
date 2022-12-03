import os

import pwndbg.commands.cymbol
import pwndbg.gdblib.dt
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


# Might be useful for future expansion of the test case
def create_symbol_file(symbol, source):
    custom_structure_example_path = (
        os.path.join(pwndbg.commands.cymbol.pwndbg_cachedir, symbol) + ".c"
    )
    with open(custom_structure_example_path, "w") as f:
        f.write(source)
    return custom_structure_example_path


def check_symbol_existance(symbol_type):
    try:
        pwndbg.gdblib.dt.dt(symbol_type)
    except Exception as exception:
        # In case it is an AttributeError symbol_type doesn't exists.
        assert isinstance(exception, AttributeError)


def test_cymbol(start_binary):
    start_binary(REFERENCE_BINARY)

    custom_structure_example = """
        typedef struct example_struct {
            int a;
            char b[16];
            char* c;
            void* d;
        } example_t;
    """
    custom_structure_example_path = create_symbol_file("example", custom_structure_example)

    # Test whether OnlyWhenStructFileExists decorator works properly
    assert pwndbg.commands.cymbol.OnlyWhenStructFileExists(lambda x, y: True)("dummy") is None
    assert pwndbg.commands.cymbol.OnlyWhenStructFileExists(lambda x, y: True)("example") is True

    # Test whether generate_debug_symbols() works properly.
    assert pwndbg.commands.cymbol.generate_debug_symbols(custom_structure_example_path) is not None

    # Test whether load_custom_structure() works properly
    pwndbg.commands.cymbol.load_custom_structure("example")
    # Test whether the symbol is loaded on the lookup loaded_symbols dict.
    assert pwndbg.commands.cymbol.loaded_symbols.get("example") is not None
    # Test whether the returned type is what we expect (on x86-64).
    assert (
        "example_t\n"
        "    +0x0000 a                    : int\n"
        "    +0x0004 b                    : char [16]\n"
        "    +0x0018 c                    : char *\n"
        "    +0x0020 d                    : void *"
    ) == pwndbg.gdblib.dt.dt("example_t").strip()

    # Test whether unload_loaded_symbol() works properly.
    pwndbg.commands.cymbol.unload_loaded_symbol("example")
    # Ensure the symbol is removed from the lookup loaded_symbols dict.
    assert pwndbg.commands.cymbol.loaded_symbols.get("example") is None
    # Ensure the symbol is no longer present in gdb.
    check_symbol_existance("example_t")

    # Load the symbol again for the next test case.
    pwndbg.commands.cymbol.load_custom_structure("example")

    # Test whether remove_custom_structure() works properly.
    pwndbg.commands.cymbol.remove_custom_structure("example")
    check_symbol_existance("example_t")
