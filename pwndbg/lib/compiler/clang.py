from __future__ import annotations

import shutil
from typing import Literal

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import DependencyNotFoundError

from .dispatch import CompilerType
from .dispatch import ToolchainInvocation
from .util import compiler_target_triple


def type() -> CompilerType:
    return CompilerType.CLANG


# Supported architectures can be obtained using the command: `clang -print-targets`
# But note that this is not necessarily equal to what clang accepts in the CPU field of
# the target triple. For instance, it will print support for x86 but not accept this
# with --triple.
_arch_mapping: dict[
    tuple[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Literal["little", "big"], int], str
] = {
    ("x86-64", "little", 8): "x86_64",
    ("i386", "little", 4): "i386",
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


def invocation_with_target(arch: ArchDefinition) -> ToolchainInvocation:
    target = compiler_target_triple(arch, _arch_mapping)
    if target is None:
        raise DependencyNotFoundError(
            "clang", f"can't find clang target for ({(arch.name, arch.endian, arch.ptrsize)})"
        )
    freestanding_target = _arch_mapping[(arch.name, arch.endian, arch.ptrsize)] + "-none-elf"

    # some distributions ship different versions of clang/llvm so a user
    # might have like llvm-20-objcopy in their PATH, but i'm ignoring this
    # case for now.
    exe = shutil.which("clang")
    if exe is None:
        raise DependencyNotFoundError("clang")


    # try to find objcopy as well
    # FIXME: it could be that llvm-objcopy is present but clang is not,
    # in this case we will not return the existence of llvm-objcopy .
    objcopy: str | None = shutil.which("llvm-objcopy")
    if objcopy is None:
        objcopy_invoc = None
    else:
        objcopy_invoc = [objcopy]

    return ToolchainInvocation(
        compiler=[
            exe,
            f"--target={target}",
        ],
        freestanding_assembler = [
            exe,
            f"--target={freestanding_target}",
            "-c"
        ],
        objcopy=objcopy_invoc, # cross-arch by default
    )
