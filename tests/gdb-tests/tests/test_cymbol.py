from __future__ import annotations

import os
import tempfile

import pwndbg.aglib.dt
import pwndbg.dbg

if pwndbg.dbg.is_gdblib_available():
    import pwndbg.commands.cymbol

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
        pwndbg.aglib.dt.dt(symbol_type)
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
    ) == pwndbg.aglib.dt.dt("example_t").strip()

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


def create_temp_header_file(content: str) -> str:
    """Create a temporary header file with the given content."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".h") as tmp_file:
        tmp_file.write(content.encode())
        return tmp_file.name


def test_cymbol_header_file(start_binary):
    start_binary(REFERENCE_BINARY)

    # Define the content of the header file
    header_content = """
    #include <stdint.h>
    typedef struct example_struct_a {
        int a;
        char b[16];
        char* c;
        void* d;
    } example_A;

    typedef struct example_struct_b {
        uint16_t X;
    } example_B;

    typedef struct example_struct_c {
        char name[32];
        int* data;
        struct example_struct_a* next;
    } example_C;
    """

    # Create a temporary header file
    header_file_path = create_temp_header_file(header_content)

    # Test adding structures from the header file
    struct_name = "example_t"

    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, struct_name)
    # Verify each structure has been loaded correctly
    assert pwndbg.commands.cymbol.loaded_symbols.get(struct_name) is not None

    # Check if the structure types match what we expect (on x86-64)
    expected_outputs = {
        "example_A": (
            "example_A\n"
            "    +0x0000 a                    : int\n"
            "    +0x0004 b                    : char [16]\n"
            "    +0x0018 c                    : char *\n"
            "    +0x0020 d                    : void *"
        ),
        "example_B": ("example_B\n    +0x0000 X                    : uint16_t"),
        "example_C": (
            "example_C\n"
            "    +0x0000 name                 : char [32]\n"
            "    +0x0020 data                 : int *\n"
            "    +0x0028 next                 : struct example_struct_a *"
        ),
    }

    # Verify structure definitions
    for struct_name, expected_output in expected_outputs.items():
        assert expected_output == pwndbg.aglib.dt.dt(struct_name).strip()

    # Test whether unload_loaded_symbol() works properly.
    pwndbg.commands.cymbol.unload_loaded_symbol("example_t")
    # Ensure the symbol is removed from the lookup loaded_symbols dict.
    assert pwndbg.commands.cymbol.loaded_symbols.get("example_t") is None
    # Ensure the symbol is no longer present in gdb.
    check_symbol_existance("example_t")

    # Load the symbol again for the next test case.
    pwndbg.commands.cymbol.load_custom_structure("example_t")

    # Test whether remove_custom_structure() works properly.
    pwndbg.commands.cymbol.remove_custom_structure("example_t")
    check_symbol_existance("example_t")
    # Clean up temp files
    os.remove(header_file_path)
