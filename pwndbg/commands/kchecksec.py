from __future__ import annotations

import argparse
from typing import NamedTuple

import pwndbg.aglib.kernel
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory


class Option(NamedTuple):
    name: str
    desired: bool = True
    cmdline_option: str = None


# TODO: Account for commandline params, module params, and sysctls

_hardening_options = [
    # Stack overflow protection
    Option("STACKPROTECTOR"),
    Option("STACKPROTECTOR_STRONG"),
    Option("SHADOW_CALL_STACK"),
    # RWX
    Option("STRICT_KERNEL_RWX"),
    Option("STRICT_MODULE_RWX"),
    Option("DEBUG_WX"),
    # ASLR
    Option("RANDOMIZE_BASE"),
    Option("RANDOMIZE_KSTACK_OFFSET_DEFAULT"),
    Option("RANDOMIZE_MODULE_REGION_FULL"),
    Option("KALLSYMS", False),
    # Memory allocation
    Option("SLAB_FREELIST_HARDENED"),
    Option("SLAB_FREELIST_RANDOM"),
    Option("KFENCE"),
    # Uninitialized data
    Option("INIT_ON_ALLOC_DEFAULT_ON"),
    Option("INIT_STACK_ALL_ZERO"),
    Option("INIT_ON_FREE_DEFAULT_ON"),
    # CFI
    Option("CFI_CLANG"),
    Option("CFI_PERMISSIVE", False),
    # Access control
    Option("SECURITY"),
    Option("SECURITY_YAMA"),
    Option("SECURITY_SELINUX_DISABLE", False),
    Option("SECURITY_SELINUX_BOOTPARAM", False),
    Option("SECURITY_SELINUX_DEVELOP", False),
    # Tracing
    Option("KPROBES", False),
    Option("FTRACE", False),
    Option("KPROBE_EVENTS", False),
    Option("UPROBE_EVENTS", False),
    Option("GENERIC_TRACER", False),
    Option("FUNCTION_TRACER", False),
    Option("STACK_TRACER", False),
    # /dev/mem
    Option("STRICT_DEVMEM"),
    Option("DEVMEM", False),
    Option("DEVKMEM", False),
    # debugfs
    Option("DEBUG_FS", False),
    Option("PTDUMP_DEBUGFS", False),
    # Misc
    Option("BUG"),
    Option("MODULES", False),
    Option("USERFAULTFD", False),
    Option("FORTIFY_SOURCE"),
    Option("STATIC_USERMODEHELPER"),
    Option("HARDENED_USERCOPY"),
    Option("RODATA_FULL_DEFAULT_ENABLED"),
    Option("RANDSTRUCT_FULL"),
    Option("TRIM_UNUSED_KSYMS"),
    Option("SECURITY_DMESG_RESTRICT"),
    Option("PROC_KCORE", False),
    Option("PROC_VMCORE", False),
    Option("COMPAT_VDSO", False),
    Option("BINFMT_MISC", False),
]

_x86_hardening_options = [
    Option("X86_SMAP"),
    Option("IA32_EMULATION", False),
    Option("X86_X32", False),
]

_arch_hardening_options = {}
_arch_hardening_options["i386"] = _x86_hardening_options
_arch_hardening_options["x86-64"] = _x86_hardening_options
_arch_hardening_options["aarch64"] = [
    Option("ARM64_PAN"),
    Option("ARM64_EPAN"),
    Option("ARM64_SW_TTBR0_PAN"),
    Option("ARM64_PTR_AUTH"),
    Option("ARM64_PTR_AUTH_KERNEL"),
    Option("ARM64_BTI"),
    Option("ARM64_BTI_KERNEL"),
    Option("ARM64_MTE"),
]

parser = argparse.ArgumentParser(description="Checks for kernel hardening configuration options.")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kchecksec() -> None:
    kconfig = pwndbg.aglib.kernel.kconfig()

    if not kconfig:
        print(
            M.warn(
                "No kernel configuration found, make sure the kernel was built with CONFIG_IKCONFIG"
            )
        )
        return

    options = _hardening_options + _arch_hardening_options.get(pwndbg.aglib.arch.name, [])
    for opt in options:
        config_name = opt.name
        val = kconfig.get(config_name)
        color_func = M.error
        if (opt.desired and val) or (not opt.desired and not val):
            color_func = M.success

        if val:
            print(color_func(f"CONFIG_{config_name} = {val}"))
        else:
            print(color_func(f"CONFIG_{config_name} not set"))
