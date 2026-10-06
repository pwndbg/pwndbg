from __future__ import annotations

import re
import shutil
import subprocess
from typing import Literal

from dispatch import CompilerType
from dispatch import ToolchainInvocation

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import DependencyNotFoundError

from .util import osabi
from .util import path_dictionary


def type() -> CompilerType:
    return CompilerType.GCC


# Alright so, in the wonderful case of gcc, the name of the compiler binary depends on what
# you supplied to ./configure when building it, so the target triple you're supposed to use
# depends on the distribution.
# e.g.
# debian / ubuntu / arch: aarch64-linux-gnu-gcc
# nixos:                  aarch64-unknown-linux-gnu-gcc
# alpine:                 aarch64-alpine-linux-musl-gcc
#        (though this is not glibc...)

# Fortunately, we are not the first to have to solve this problem of
# gcc toolchain autodetection:
# https://github.com/llvm/llvm-project/blob/d7225c0591ba1b79afca445f73b0d1c84e9a5d83/clang/lib/Driver/ToolChains/Gnu.cpp#L2108
# https://github.com/rust-lang/cc-rs/blob/2ac0cd630dbdd2829d1d7b7ac4415aaf5c8a6f19/src/lib.rs#L4318

# Unfortunately, the solutions are quite chonky, and I would rather not have all that
# complexity here.

# Still, the arch name should be pretty consistent.
# Taken from the rust link above. Could be improved.
_arch_mapping: dict[
    tuple[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Literal["little", "big"], int], str
] = {
    ("x86-64", "little", 8): "x86_64",
    ("i386", "little", 4): "x86_64",  # we're just gonna pass -m32
    ("mips", "big", 4): "mips",
    ("mips", "little", 4): "mipsel",
    ("mips", "big", 8): "mips64",
    ("mips", "little", 8): "mips64el",
    ("aarch64", "little", 8): "aarch64",
    ("arm", "little", 4): "arm",  # we need to pass in -marm
    ("arm", "big", 4): "armeb",  # -marm
    ("armcm", "little", 4): "arm",  # -mthumb
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


def triple_from_gcc(gcc_invocation: list[str]) -> str:
    """
    Runs `gcc -dumpmachine` to get what target triple this gcc
    can compile for.

    Returns empty string if something went wrong.
    """
    try:
        result = subprocess.run(
            gcc_invocation + ["-dumpmachine"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def additional_flags(arch: ArchDefinition) -> list[str]:
    """
    To compile some architectures, it's not enough to use the correct target triple,
    but we need to pass additional flags as well.
    """
    if arch.name == "x86-64":
        return ["-m64"]
    if arch.name == "i386":
        return ["-m32"]
    if arch.name == "arm":
        return ["-marm"]
    if arch.name == "armcm":
        return ["-mthumb"]

    return []


# allows versioned gcc as well
gcc_driver_re = re.compile(r"^(.+-)?gcc(-[0-9]+(\.[0-9]+)*)?$")


def invocation_with_target(arch: ArchDefinition) -> ToolchainInvocation:
    osabi_ = osabi(arch)
    if osabi_ is None:
        raise DependencyNotFoundError(
            "gcc", f"can't find gcc OS ABI for ({(arch.name, arch.endian, arch.ptrsize)})"
        )
    gcc_cpu = _arch_mapping.get((arch.name, arch.endian, arch.ptrsize))
    if gcc_cpu is None:
        raise DependencyNotFoundError(
            "gcc", f"can't find gcc target for ({(arch.name, arch.endian, arch.ptrsize)})"
        )

    # The most common case first, lets see if the `gcc` binary supports
    # the target arch.
    gcc = shutil.which("gcc")
    if gcc is not None:
        triple = triple_from_gcc([gcc])
        if gcc_cpu in triple and (osabi_ in triple or "-none-eabi" in triple):
            # Okay we're good!

            # Make sure that objcopy exists, we assume it supports the same stuff.
            objcopy: str | None = shutil.which("objcopy")
            if objcopy is None:
                objcopy_invoc = None
            else:
                objcopy_invoc = [objcopy]

            return ToolchainInvocation(
                compiler=[gcc] + additional_flags(arch),
                freestanding_assembler=[gcc] + additional_flags(arch) + ["-c"],
                objcopy=objcopy_invoc,
            )

    # Okay, now the messy part of searching for the right binary
    path_dict: dict[str, str] = path_dictionary()
    for name, driver_path in path_dict.items():
        if not gcc_driver_re.match(name):
            continue

        driver_triple = name.split("gcc")[0]
        driver_cpu = driver_triple.split("-")[0]

        # Check if the cpu and OS ABI are correct
        if gcc_cpu == driver_cpu and (osabi_ in driver_triple or "-none-eabi" in driver_triple):
            # They are!!!

            # Make sure objcopy exists under the same triple prefix
            objcopy = shutil.which(f"{driver_triple}objcopy")
            if objcopy is None:
                objcopy_invoc = None
            else:
                objcopy_invoc = [objcopy]

            return ToolchainInvocation(
                compiler=[driver_path] + additional_flags(arch),
                freestanding_assembler=[driver_path] + additional_flags(arch) + ["-c"],
                objcopy=objcopy_invoc,
            )

    raise DependencyNotFoundError(
        "gcc",
        f"can't find gcc for {(arch.name, arch.endian, arch.ptrsize)}, tried gcc prefix {gcc_cpu}",
    )
