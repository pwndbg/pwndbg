from __future__ import annotations

import os
from pathlib import Path

import gdb

import pwndbg
import pwndbg.aglib.dt
import pwndbg.aglib.structures

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


# Might be useful for future expansion of the test case
def create_struct_file(name: str, source: str) -> Path:
    path = pwndbg.aglib.structures.get_struct_path(name)
    with open(path, "w") as f:
        f.write(source)
    return path


def check_type_doesnt_exist(name: str) -> None:
    try:
        pwndbg.aglib.dt.dt(name)
    except Exception as exception:
        # In case it is an AttributeError symbol_type doesn't exists.
        assert isinstance(exception, AttributeError)


def test_cymbol(start_binary) -> None:
    start_binary(REFERENCE_BINARY)

    example_struct_body = """
        typedef struct example_struct {
            int a;
            char b[16];
            char* c;
            void* d;
        } example_t;
    """
    example_struct: Path = create_struct_file("example", example_struct_body)

    # Test whether get_struct_path_if_exists works properly decorator works properly
    assert pwndbg.aglib.structures.get_struct_path_if_exists("dummy") is None
    assert pwndbg.aglib.structures.get_struct_path_if_exists("example") is not None

    # Test whether generate_debug_symbols() works properly.
    assert pwndbg.aglib.structures.compile_structure(example_struct)[1].is_success()

    # Test whether load_custom_structure() works properly
    gdb.execute("cymbol load example")
    # Test whether the symbol is loaded on the lookup loaded_symbols dict.
    assert pwndbg.aglib.structures.loaded_structures.get("example") is not None
    # Test whether the returned type is what we expect (on x86-64).
    assert (
        "example_t\n"
        "    +0x0000 a                    : int\n"
        "    +0x0004 b                    : char [16]\n"
        "    +0x0018 c                    : char *\n"
        "    +0x0020 d                    : void *"
    ) == pwndbg.aglib.dt.dt("example_t").strip()

    # Test whether unload() works properly.
    pwndbg.aglib.structures.unload("example")
    # Ensure the structure is removed from the lookup loaded_structures dict.
    assert pwndbg.aglib.structures.loaded_structures.get("example") is None
    # Ensure the type is no longer present in gdb.
    check_type_doesnt_exist("example_t")

    # Load the type again for the next test case.
    gdb.execute("cymbol load example")

    # Test whether remove_custom_structure() works properly.
    gdb.execute("cymbol remove example")
    check_type_doesnt_exist("example_t")


def test_cymbol_header_file(start_binary) -> None:
    start_binary(REFERENCE_BINARY)

    # Define the content of the header file
    header_content: str = """
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
    header_file_path: Path = pwndbg.aglib.structures.create_temp_header_file(header_content)

    # Test adding structures from the header file
    struct_name: str = "example_t"

    gdb.execute(f"cymbol file {header_file_path} --name {struct_name}")
    # Verify each structure has been loaded correctly
    assert pwndbg.aglib.structures.loaded_structures.get(struct_name) is not None

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

    # Test whether unload() works properly.
    pwndbg.aglib.structures.unload(struct_name)
    # Ensure the type is removed from the lookup loaded_symbols dict.
    assert pwndbg.aglib.structures.loaded_structures.get(struct_name) is None
    # Ensure the symbol is no longer present in gdb.
    check_type_doesnt_exist(struct_name)

    # Load the symbol again for the next test case.
    gdb.execute(f"cymbol load {struct_name}")

    # Test whether remove_custom_structure() works properly.
    gdb.execute(f"cymbol remove {struct_name}")
    check_type_doesnt_exist("example_t")
    # Clean up temp files
    os.remove(header_file_path)
