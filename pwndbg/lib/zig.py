from __future__ import annotations

import os.path
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


def flags(arch: ArchDefinition) -> List[str] | None:
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
