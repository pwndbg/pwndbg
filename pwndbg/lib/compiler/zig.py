from __future__ import annotations

import os
import os.path
import shutil
import subprocess
from typing import Literal

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import DependencyNotFoundError

from .dispatch import CompilerType
from .dispatch import ToolchainInvocation
from .util import compiler_target_triple


def type() -> CompilerType:
    return CompilerType.ZIG


# Supported architectures can be obtained using the command: `zig targets`
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

def additional_flags(arch: ArchDefinition) -> list[str]:
    """
    To compile some architectures, it's not enough to use the correct target triple,
    but we need to pass additional flags as well.
    """

    # Just using sparc-freestanding target will fail compilation (as of Zig 0.17.0).
    # We need to specify a target CPU
    if arch.name == "sparc" and arch.ptrsize == 4:
        return ["-mcpu=v8"]

    return []


LOWEST_ZIG_SUPPORTED_VERSION = (0, 15, 2)


def _get_executable() -> str:
    """
    Get the path to the zig executable.
    Precedence: ziglang module, zig in PATH.

    Raises:
        DependencyNotFoundError: zig could not be found or is an unsupported version
    """
    try:
        import ziglang  # type: ignore[import-untyped]

        if ziglang.__file__ is not None:
            return os.path.join(os.path.dirname(ziglang.__file__), "zig")
    except ImportError:
        pass

    zig_path = shutil.which("zig")
    if zig_path is None:
        raise DependencyNotFoundError(
            "zig", "python module ziglang not available and zig not found in PATH"
        )

    try:
        result = subprocess.run(
            [zig_path, "version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        version = tuple([int(num) for num in result.stdout.strip().split("-")[0].split(".")])
        if version < LOWEST_ZIG_SUPPORTED_VERSION:
            raise DependencyNotFoundError(
                "zig",
                f"unsupported zig version: {version}. "
                f"only versions >={LOWEST_ZIG_SUPPORTED_VERSION} are supported.",
            )
    except Exception as e:
        raise DependencyNotFoundError("zig", f"failed to check zig version at {zig_path}: {e}")

    return zig_path


def invocation_with_target(arch: ArchDefinition) -> ToolchainInvocation:
    zig_target = compiler_target_triple(arch, _arch_mapping)
    if zig_target is None:
        raise DependencyNotFoundError(
            "zig", f"can't find zig target for ({(arch.name, arch.endian, arch.ptrsize)})"
        )
    freestanding_target = _arch_mapping[(arch.name, arch.endian, arch.ptrsize)] + "-freestanding"

    # may throw
    zig_executable = _get_executable()

    return ToolchainInvocation(
        compiler=[
            zig_executable,
            "cc",
            "-target",
            zig_target,
        ] + additional_flags(arch),
        freestanding_assembler=[zig_executable, "cc", "-target", freestanding_target] + additional_flags(arch) + ["-c"],
        objcopy=[zig_executable, "objcopy"],  # it is cross-arch by default
    )
