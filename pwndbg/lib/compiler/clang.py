from __future__ import annotations

import shutil
from typing import Literal

from dispatch import CompilerType

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import DependencyNotFoundError

from .util import compiler_target_triple


def type() -> CompilerType:
    return CompilerType.CLANG


# Supported architectures can be obtained using the command: `clang -print-targets`
_arch_mapping: dict[
    tuple[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Literal["little", "big"], int], str
] = {
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
    ("rv32", "big", 4): "riscv32be",
    ("rv64", "little", 8): "riscv64",
    ("rv64", "big", 8): "riscv64be",
    ("sparc", "big", 4): "sparc",
    ("sparc", "little", 4): "sparcel",
    ("sparc", "big", 8): "sparcv9",  # sparc64 also works
    ("powerpc", "big", 4): "ppc32",
    ("powerpc", "little", 4): "ppc32le",
    ("powerpc", "big", 8): "ppc64",
    ("powerpc", "little", 8): "ppc64le",
    ("loongarch64", "little", 8): "loongarch64",
    ("s390x", "big", 8): "systemz",  # s390x also works
}

def _get_executable() -> str:
    """
    Get the path to the clang executable.

    Raises:
        DependencyNotFoundError: clang could not be found
    """
    path = shutil.which("clang")
    if path is None:
        raise DependencyNotFoundError("clang")

    return path

def invocation_with_target(arch: ArchDefinition) -> list[str]:
    # may throw
    execu = _get_executable()

    target = compiler_target_triple(arch, _arch_mapping)
    if target is None:
        raise DependencyNotFoundError(
            "clang", f"can't find clang target for ({(arch.name, arch.endian, arch.ptrsize)})"
        )

    return [
        execu,
        f"--target={target}",
    ]
