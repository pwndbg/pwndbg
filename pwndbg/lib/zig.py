import subprocess
import os.path
from typing import Dict, Tuple, Literal, List
from pwndbg.lib.arch import ArchDefinition, PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

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
    if arch.platform == 'linux':
        # "gnu", "gnuabin32", "gnuabi64", "gnueabi", "gnueabihf",
        # "gnuf32","gnusf", "gnux32", "gnuilp32",
        # TODO: support soft/hard float abi?
        osabi = "linux-gnu"
    else:
        osabi = "macos-none"

    arch_mapping = _arch_mapping.get((arch.name, arch.endian, arch.ptrsize), None)
    if arch_mapping is None:
        return None

    return arch_mapping + '-' + osabi


def flags(arch: ArchDefinition) -> List[str] | None:
    try:
        import ziglang
    except ImportError:
        raise ValueError("Can't import ziglang")

    zig_target = _get_zig_target(arch)
    if zig_target is None:
        raise ValueError("Can't find ziglang target")

    return [
        os.path.join(os.path.dirname(ziglang.__file__), "zig"),
        "cc",
        "-target",
        zig_target,
    ]
