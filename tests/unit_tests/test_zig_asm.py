from __future__ import annotations

import pathlib
import tempfile

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

import pwndbg.lib.zig

expected_value = 60
include_text = f"""
#define FROM_INCLUDE_VALUE {expected_value}
"""

regs_and_instr = {
    "x86": (
        "mov eax, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_X86,
        uc.UC_MODE_32,
        None,
        x86_const.UC_X86_REG_EAX,
    ),
    "x86_64": (
        "mov rax, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_X86,
        uc.UC_MODE_64,
        None,
        x86_const.UC_X86_REG_RAX,
    ),
    "mips": (
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS32 | uc.UC_MODE_BIG_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mipsel": (
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mips64": (
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS64 | uc.UC_MODE_BIG_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "mips64el": (
        "li $a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_MIPS,
        uc.UC_MODE_MIPS64 | uc.UC_MODE_LITTLE_ENDIAN,
        None,
        mips_const.UC_MIPS_REG_A0,
    ),
    "arm": (
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_ARM,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "armeb": (
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_ARM | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "thumb": (
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_THUMB,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "thumbeb": (
        "mov r0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM,
        uc.UC_MODE_THUMB | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm_const.UC_ARM_REG_R0,
    ),
    "aarch64": (
        "mov x0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM64,
        uc.UC_MODE_ARM,
        None,
        arm64_const.UC_ARM64_REG_X0,
    ),
    "aarch64_be": (
        "mov x0, #FROM_INCLUDE_VALUE",
        uc.UC_ARCH_ARM64,
        uc.UC_MODE_ARM | uc.UC_MODE_BIG_ENDIAN,
        None,
        arm64_const.UC_ARM64_REG_X0,
    ),
    "riscv32": (
        "li a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_RISCV,
        uc.UC_MODE_RISCV32,
        None,
        riscv_const.UC_RISCV_REG_A0,
    ),
    "riscv64": (
        "li a0, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_RISCV,
        uc.UC_MODE_RISCV64,
        None,
        riscv_const.UC_RISCV_REG_A0,
    ),
    "s390x": (
        "lghi %r2, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_S390X,
        uc.UC_MODE_BIG_ENDIAN,
        s390x_const.UC_CPU_S390X_Z14,
        s390x_const.UC_S390X_REG_R2,
    ),
    # FIXME: upstream bug, https://github.com/ziglang/zig/issues/23674
    # 'sparc':        ('mov 60,%i0', uc.UC_ARCH_SPARC, uc.UC_MODE_SPARC32 | uc.UC_MODE_BIG_ENDIAN, None, sparc_const.UC_SPARC_REG_I0),
    "sparc64": (
        "mov FROM_INCLUDE_VALUE,%i0",
        uc.UC_ARCH_SPARC,
        uc.UC_MODE_SPARC64 | uc.UC_MODE_BIG_ENDIAN,
        None,
        sparc_const.UC_SPARC_REG_I0,
    ),
    "powerpc": (
        "li %r1, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_PPC,
        uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN,
        ppc_const.UC_CPU_PPC32_7457A_V1_2,
        ppc_const.UC_PPC_REG_1,
    ),
    "powerpc64": (
        "li %r1, FROM_INCLUDE_VALUE",
        uc.UC_ARCH_PPC,
        uc.UC_MODE_64 | uc.UC_MODE_BIG_ENDIAN,
        ppc_const.UC_CPU_PPC64_970_V2_2,
        ppc_const.UC_PPC_REG_1,
    ),
    "powerpcle": (
        "li %r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: UC_MODE_LITTLE_ENDIAN, Not supported by Unicorn
    "powerpc64le": (
        "li %r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: UC_MODE_LITTLE_ENDIAN, Not supported by Unicorn
    "loongarch64": (
        "addi.d $r1, $r1, FROM_INCLUDE_VALUE",
        None,
        None,
        None,
        None,
    ),  # FIXME: Not supported by Unicorn
}
test_cases = list(regs_and_instr.keys())


@pytest.mark.parametrize("arch", test_cases)
def test_zig_asm_compiles(arch):
    asm_line, uc_arch, uc_mode, uc_cpu, reg_id = regs_and_instr[arch]

    with tempfile.NamedTemporaryFile(mode="wt", suffix="test.h", delete=False) as example_h:
        example_h.write(include_text)

    bytecode = pwndbg.lib.zig._asm(arch, asm_line, includes=[pathlib.Path(example_h.name)])
    assert len(bytecode) > 0, "Bytecode too short"

    if uc_arch is None:
        pytest.skip("unsupported by Unicorn")

    mu = uc.Uc(uc_arch, uc_mode, uc_cpu)

    # Map 4KB memory at 0x20000
    ADDRESS = 0x20000
    mu.mem_map(ADDRESS, 0x2000)
    mu.mem_write(ADDRESS, bytes(bytecode))

    # Zero the register
    mu.reg_write(reg_id, 0)

    # Run the code
    mu.emu_start(ADDRESS, ADDRESS + len(bytecode), count=1)

    # Read result
    value = mu.reg_read(reg_id)
    assert value == expected_value, "Value mismatch"
