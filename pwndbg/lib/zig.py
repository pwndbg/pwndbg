from __future__ import annotations

import os.path
import pathlib
import subprocess
import tempfile
from typing import Dict
from typing import List
from typing import Literal
from typing import Tuple

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform

# Supported architectures can be obtained using the command: `zig targets`
_arch_mapping: Dict[Tuple[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Literal["little", "big"], int], str] = {
    ("x86-64", "little", 8): "x86_64",
    ("i386", "little", 4): "x86",
    ("mips", "big", 4): "mips",
    ("mips", "little", 4): "mipsel",
    ("mips", "big", 8): "mips64",
    ("mips", "little", 8): "mips64el",
    ("aarch64", "little", 8): "aarch64",
    ("aarch64", "big", 8): "aarch64_be",
    ("arm", "little", 4): "arm",
    ("arm", "big", 4): "armeb",
    ("armcm", "little", 4): "thumb",
    ("armcm", "big", 4): "thumbeb",
    ("rv32", "little", 4): "riscv32",
    ("rv64", "little", 8): "riscv64",
    ("sparc", "big", 4): "sparc",
    ("sparc", "big", 8): "sparc64",
    ("powerpc", "big", 4): "powerpc",
    ("powerpc", "little", 4): "powerpcle",
    ("powerpc", "big", 8): "powerpc64",
    ("powerpc", "little", 8): "powerpc64le",
    ("loongarch64", "little", 8): "loongarch64",
    ("s390x", "big", 8): "s390x",
}

_prefix_header = ".global _start\n.global __start\n.section .text\n_start:\n__start:\n"
_asm_header: Dict[str, str] = {
    # `.intel_syntax noprefix` forces the use of Intel assembly syntax instead of AT&T
    "x86_64": _prefix_header + ".intel_syntax noprefix\n",
    "x86": _prefix_header + ".intel_syntax noprefix\n",

    # `.set noreorder` disables instruction reordering for MIPS to handle delay slots correctly
    "mips": _prefix_header + ".set noreorder\n",
    "mipsel": _prefix_header + ".set noreorder\n",
    "mips64": _prefix_header + ".set noreorder\n",
    "mips64el": _prefix_header + ".set noreorder\n",
    "aarch64": _prefix_header,
    "aarch64_be": _prefix_header,

    # `.syntax unified` enables the unified assembly syntax for ARM/Thumb
    "arm": _prefix_header + ".syntax unified\n",
    "armeb": _prefix_header + ".syntax unified\n",
    "thumb": _prefix_header + ".syntax unified\n",
    "thumbeb": _prefix_header + ".syntax unified\n",
    "riscv32": _prefix_header,
    "riscv64": _prefix_header,
    "sparc": _prefix_header,
    "sparc64": _prefix_header,
    "powerpc": _prefix_header,
    "powerpcle": _prefix_header,
    "powerpc64": _prefix_header,
    "powerpc64le": _prefix_header,
    "loongarch64": _prefix_header,
    "s390x": _prefix_header,
}

def _get_zig_target(arch: ArchDefinition) -> str | None:
    if arch.platform == Platform.LINUX:
        # "gnu", "gnuabin32", "gnuabi64", "gnueabi", "gnueabihf",
        # "gnuf32","gnusf", "gnux32", "gnuilp32",
        # TODO: support soft/hard float abi?
        osabi = "linux-gnu"
    elif arch.platform == Platform.DARWIN:
        osabi = "macos-none"
    else:
        return None

    arch_mapping = _arch_mapping.get((arch.name, arch.endian, arch.ptrsize), None)
    if arch_mapping is None:
        return None

    return f"{arch_mapping}-{osabi}"


def flags(arch: ArchDefinition) -> List[str]:
    try:
        import ziglang  # type: ignore[import-untyped]
    except ImportError:
        raise ValueError("Can't import ziglang")

    zig_target = _get_zig_target(arch)
    if zig_target is None:
        raise ValueError(f"Can't find ziglang target for ({(arch.name, arch.endian, arch.ptrsize)})")

    return [
        os.path.join(os.path.dirname(ziglang.__file__), "zig"),
        "cc",
        "-target",
        zig_target,
    ]


def asm(arch: ArchDefinition, data: str, includes: List[pathlib.Path] | None=None) -> bytes:
    arch_mapping = _arch_mapping.get((arch.name, arch.endian, arch.ptrsize), None)
    if arch_mapping is None:
        raise ValueError(f"Can't find ziglang target for ({(arch.name, arch.endian, arch.ptrsize)})")

    return _asm(arch_mapping, data, includes)


def _asm(arch_mapping: str, data: str, includes: List[pathlib.Path] | None=None) -> bytes:
    try:
        import ziglang
    except ImportError:
        raise ValueError("Can't import ziglang")

    header = _asm_header.get(arch_mapping, None)
    if header is None:
        raise ValueError(f"Can't find asm header for target {arch_mapping}")

    if includes is None:
        includes = []

    includes = ''.join((f'#include "{path}"\n' for path in includes))
    target = f'{arch_mapping}-freestanding'

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_file = os.path.join(tmpdir, "input.S")
        compiled_file = os.path.join(tmpdir, "out.elf")
        bytecode_file = os.path.join(tmpdir, "out.bytecode")

        with open(asm_file, "w") as f:
            f.write(includes)
            f.write(header)
            f.write(data)

        # Build the binary with Zig
        compile_process = subprocess.run(
            [
                os.path.join(os.path.dirname(ziglang.__file__), "zig"),
                "cc",
                "-target",
                target,
                asm_file,
                "-o",
                compiled_file,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            raise Exception("Compilation error", compile_process.stdout, compile_process.stderr)

        # Extract bytecode
        objcopy_process = subprocess.run(
            [
                os.path.join(os.path.dirname(ziglang.__file__), "zig"),
                "objcopy",
                "-O",
                "binary",
                "--only-section=.text",
                compiled_file,
                bytecode_file,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if objcopy_process.returncode != 0:
            raise Exception("Extracting bytecode error", objcopy_process.stdout, objcopy_process.stderr)

        with open(bytecode_file, "rb") as f:
            return f.read()
