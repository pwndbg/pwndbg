from __future__ import annotations

import pathlib

import pytest
import unicorn as uc
from unicorn import arm64_const
from unicorn import arm_const
from unicorn import mips_const
from unicorn import ppc_const
from unicorn import riscv_const
from unicorn import s390x_const
from unicorn import sparc_const
from unicorn import x86_const

import pwndbg.lib.cache
import pwndbg.lib.compiler
import pwndbg.lib.compiler.clang
import pwndbg.lib.compiler.facade
import pwndbg.lib.compiler.gcc
import pwndbg.lib.compiler.zig
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform
from pwndbg.lib.compiler import Compiler
from pwndbg.lib.err import CompilerNotFoundError
from pwndbg.lib.err import DependencyNotFoundError

expected_value = 60
include_text = f"""
#define FROM_INCLUDE_VALUE {expected_value}
"""

compilers: dict[str, Compiler] = {
    "zig": pwndbg.lib.compiler.zig,
    "clang": pwndbg.lib.compiler.clang,
    "gcc": pwndbg.lib.compiler.gcc,
}

regs_and_instr = {
    "x86": (
        ArchDefinition(name="i386", ptrsize=4, endian="little", platform=Platform.LINUX),
        "mov eax, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_X86,
        uc.UC_MODE_32,
        None,
        x86_const.UC_X86_REG_EAX,
    ),
    "x86_64": (
        ArchDefinition(name="x86-64", ptrsize=8, endian="little", platform=Platform.LINUX),
        "mov rax, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_X86,
        uc.UC_MODE_64,
        None,
        x86_const.UC_X86_REG_RAX,
    ),
    "mips": (
        ArchDefinition(name="mips", ptrsize=4, endian="big", platform=Platform.LINUX),
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS32 | uc.UC_MODE_BIG_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mipsel": (
        ArchDefinition(name="mips", ptrsize=4, endian="little", platform=Platform.LINUX),
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mips64": (
        ArchDefinition(name="mips", ptrsize=8, endian="big", platform=Platform.LINUX),
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS64 | uc.UC_MODE_BIG_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mips64el": (
        ArchDefinition(name="mips", ptrsize=8, endian="little", platform=Platform.LINUX),
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS64 | uc.UC_MODE_LITTLE_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "arm": (
        ArchDefinition(name="arm", ptrsize=4, endian="little", platform=Platform.LINUX),
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_ARM,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "armeb": (
        ArchDefinition(name="arm", ptrsize=4, endian="big", platform=Platform.LINUX),
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_ARM | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "thumb": (
        ArchDefinition(name="armcm", ptrsize=4, endian="little", platform=Platform.LINUX),
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_THUMB,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "thumbeb": (
        ArchDefinition(name="armcm", ptrsize=4, endian="big", platform=Platform.LINUX),
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_THUMB | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "aarch64": (
        ArchDefinition(name="aarch64", ptrsize=8, endian="little", platform=Platform.LINUX),
        "mov x0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM64,
        uc.UC_MODE_ARM,
        None,
        arm64_const.UC_ARM64_REG_X0,
    ),
    "aarch64_be": (
        ArchDefinition(name="aarch64", ptrsize=8, endian="big", platform=Platform.LINUX),
        "mov x0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM64,
        uc.UC_MODE_ARM | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm64_const.UC_ARM64_REG_X0,
    ),
    "riscv32": (
        ArchDefinition(name="rv32", ptrsize=4, endian="little", platform=Platform.LINUX),
        "li a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_RISCV,
        uc.UC_MODE_RISCV32,
        None,
        riscv_const.UC_RISCV_REG_A0,
    ),
    "riscv64": (
        ArchDefinition(name="rv64", ptrsize=8, endian="little", platform=Platform.LINUX),
        "li a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_RISCV,
        uc.UC_MODE_RISCV64,
        None,
        riscv_const.UC_RISCV_REG_A0,
    ),
    "s390x": (
        ArchDefinition(name="s390x", ptrsize=8, endian="big", platform=Platform.LINUX),
        "lghi %r2, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_S390X,
        uc.UC_MODE_BIG_ENDIAN,
        s390x_const.UC_CPU_S390X_Z14,
        s390x_const.UC_S390X_REG_R2,
    ),
    "sparc": (
        ArchDefinition(name="sparc", ptrsize=4, endian="big", platform=Platform.LINUX),
        "mov 60,%i0",
        uc.UC_ARCH_SPARC,
        uc.UC_MODE_SPARC32 | uc.UC_MODE_BIG_ENDIAN,
        None,
        sparc_const.UC_SPARC_REG_I0,
    ),
    "sparc64": (
        ArchDefinition(name="sparc", ptrsize=8, endian="big", platform=Platform.LINUX),
        "mov FROM_INCLUDE_VALUE,%i0",
        uc.UC_ARCH_SPARC,
        uc.UC_MODE_SPARC64 | uc.UC_MODE_BIG_ENDIAN,
        None,
        sparc_const.UC_SPARC_REG_I0,
    ),
    "powerpc": (
        ArchDefinition(name="powerpc", ptrsize=4, endian="big", platform=Platform.LINUX),
        "li %r1, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_PPC,
        uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN,
        ppc_const.UC_CPU_PPC32_7457A_V1_2,
        ppc_const.UC_PPC_REG_1,
    ),
    "powerpc64": (
        ArchDefinition(name="powerpc", ptrsize=8, endian="big", platform=Platform.LINUX),
        "li %r1, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_PPC,
        uc.UC_MODE_64 | uc.UC_MODE_BIG_ENDIAN,
        ppc_const.UC_CPU_PPC64_970_V2_2,
        ppc_const.UC_PPC_REG_1,
    ),
    "powerpcle": (
        ArchDefinition(name="powerpc", ptrsize=4, endian="little", platform=Platform.LINUX),
        "li %r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: UC_MODE_LITTLE_ENDIAN, Not supported by Unicorn
    "powerpc64le": (
        ArchDefinition(name="powerpc", ptrsize=8, endian="little", platform=Platform.LINUX),
        "li %r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: UC_MODE_LITTLE_ENDIAN, Not supported by Unicorn
    "loongarch64": (
        ArchDefinition(name="loongarch64", ptrsize=8, endian="little", platform=Platform.LINUX),
        "addi.d $r1, $r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: Not supported by Unicorn
}
test_cases = list(regs_and_instr.keys())


@pytest.mark.parametrize("compiler", compilers.values(), ids=compilers.keys())
@pytest.mark.parametrize("arch", test_cases)
def test_asm_compiles(
    arch: str, compiler: Compiler, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arch_def, asm_line, uc_arch, uc_mode, uc_cpu, reg_id = regs_and_instr[arch]

    example_h = tmp_path / "test.h"
    example_h.write_text(include_text)

    # Force the facade to use the currently tested compiler
    monkeypatch.setattr(pwndbg.lib.compiler.facade, "_compilers", (compiler,))
    pwndbg.lib.cache.clear_caches()
    try:
        bytecode = pwndbg.lib.compiler.asm(arch_def, asm_line, includes=[example_h])
    except (DependencyNotFoundError, CompilerNotFoundError):
        pytest.skip(f"{compiler.type()} doesn't support {arch_def}")
    finally:
        pwndbg.lib.cache.clear_caches()

    assert len(bytecode) > 0, "Bytecode too short"

    if uc_arch is None:
        pytest.skip("unsupported by Unicorn")

    # mypy only sees the python2 declaration?
    mu = uc.unicorn.Uc(uc_arch, uc_mode, uc_cpu)  # type: ignore[call-arg]

    # Map 4KB memory at 0x20000
    ADDRESS = 0x20000
    mu.mem_map(ADDRESS, 0x2000)
    mu.mem_write(ADDRESS, bytes(bytecode))

    # Zero the register
    mu.reg_write(reg_id, 0)

    # Need `ADDRESS | 1` for thumb
    start = ADDRESS | 1 if uc_mode & uc.UC_MODE_THUMB else ADDRESS

    # Run the code
    mu.emu_start(start, ADDRESS + len(bytecode), count=1)

    # Read result
    value = mu.reg_read(reg_id)
    assert value == expected_value, "Value mismatch"
