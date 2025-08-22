from __future__ import annotations

import argparse
import struct

import tabulate

import pwndbg
import pwndbg.aglib.memory
import pwndbg.commands
from pwndbg.commands import CommandCategory

RW_FLAGS = 4 | 2
RO_FLAGS = 4

FIELDS_X86 = (
    (RW_FLAGS, "_COMM_PAGE_SIGNATURE", 0x000, "16s", "First 16 bytes, commpage signature"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CAPABILITIES64", 0x010, "Q", "CPU capabilities (64-bit)"),
    (RW_FLAGS, "_COMM_PAGE_VERSION", 0x01E, "H", "Commpage version number"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CAPABILITIES", 0x020, "I", "CPU capabilities (32-bit, legacy)"),
    (RW_FLAGS, "_COMM_PAGE_NCPUS", 0x022, "B", "Number of configured CPUs"),
    (RW_FLAGS, "_COMM_PAGE_CACHE_LINESIZE", 0x026, "H", "CPU cache line size"),
    (RW_FLAGS, "_COMM_PAGE_MEMORY_PRESSURE", 0x02C, "I", "VM memory pressure"),
    (RW_FLAGS, "_COMM_PAGE_ACTIVE_CPUS", 0x034, "B", "Number of active CPUs"),
    (RW_FLAGS, "_COMM_PAGE_PHYSICAL_CPUS", 0x035, "B", "Number of physical CPUs (max)"),
    (RW_FLAGS, "_COMM_PAGE_LOGICAL_CPUS", 0x036, "B", "Number of logical CPUs (max)"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CLUSTERS", 0x037, "B", "Number of CPU clusters"),
    (RW_FLAGS, "_COMM_PAGE_MEMORY_SIZE", 0x038, "Q", "Maximum memory size"),
    (RW_FLAGS, "_COMM_PAGE_CPUFAMILY", 0x040, "I", "CPU family identifier"),
    (RW_FLAGS, "_COMM_PAGE_KDEBUG_ENABLE", 0x044, "I", "Exported kernel kdebug_enable"),
    (RW_FLAGS, "_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG", 0x048, "I", "Exported atm_diagnostic_config"),
    (RW_FLAGS, "_COMM_PAGE_DTRACE_DOF_ENABLED", 0x04C, "B", "DTrace DOF enabled flag"),
    (RW_FLAGS, "_COMM_PAGE_KERNEL_PAGE_SHIFT", 0x04D, "B", "Kernel VM page shift"),
    (RW_FLAGS, "_COMM_PAGE_USER_PAGE_SHIFT_64", 0x04E, "B", "User VM page shift (64-bit)"),
    (RW_FLAGS, "_COMM_PAGE_NT_TSC_BASE", 0x050, "Q", "Nanotime TSC base"),
    (RW_FLAGS, "_COMM_PAGE_NT_SCALE", 0x058, "Q", "Nanotime scale"),
    (RW_FLAGS, "_COMM_PAGE_NT_SHIFT", 0x05C, "I", "Nanotime shift"),
    (RW_FLAGS, "_COMM_PAGE_NT_NS_BASE", 0x060, "Q", "Nanotime ns base"),
    (RW_FLAGS, "_COMM_PAGE_NT_GENERATION", 0x068, "I", "Nanotime generation counter"),
    (RW_FLAGS, "_COMM_PAGE_GTOD_GENERATION", 0x06C, "I", "gettimeofday() generation counter"),
    (RW_FLAGS, "_COMM_PAGE_GTOD_NS_BASE", 0x070, "Q", "gettimeofday() ns base"),
    (RW_FLAGS, "_COMM_PAGE_GTOD_SEC_BASE", 0x078, "Q", "gettimeofday() sec base"),
    (RW_FLAGS, "_COMM_PAGE_APPROX_TIME", 0x080, "Q", "mach_approximate_time() value"),
    (
        RW_FLAGS,
        "_COMM_PAGE_APPROX_TIME_SUPPORTED",
        0x088,
        "I",
        "mach_approximate_time() supported flag",
    ),
    (RW_FLAGS, "_COMM_PAGE_CONT_TIMEBASE", 0x0C0, "Q", "mach_continuous_time() base"),
    (RW_FLAGS, "_COMM_PAGE_BOOTTIME_USEC", 0x0C8, "Q", "System boottime (usec)"),
    (RW_FLAGS, "_COMM_PAGE_DYLD_FLAGS", 0x100, "Q", "Exported dyld_system_flags"),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_VALUE",
        0x320,
        "Q",
        "Apple Security Bounty: random target value",
    ),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_ADDRESS",
        0x328,
        "Q",
        "Apple Security Bounty: random target address",
    ),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_KERN_VALUE",
        0x330,
        "Q",
        "Apple Security Bounty: random kernel value",
    ),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_KERN_ADDR",
        0x338,
        "Q",
        "Apple Security Bounty: random kernel address",
    ),
)

FIELDS_ARM = (
    (RW_FLAGS, "_COMM_PAGE_SIGNATURE", 0x000, "16s", "Commpage signature"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CAPABILITIES64", 0x010, "Q", "CPU capabilities (64-bit)"),
    (RW_FLAGS, "_COMM_PAGE_VERSION", 0x01E, "H", "Commpage version number"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CAPABILITIES", 0x020, "I", "CPU capabilities (32-bit)"),
    (RW_FLAGS, "_COMM_PAGE_NCPUS", 0x022, "B", "Number of configured CPUs"),
    (
        RW_FLAGS,
        "_COMM_PAGE_USER_PAGE_SHIFT_32_LEGACY",
        0x024,
        "B",
        "VM page shift for 32-bit processes (legacy mapping)",
    ),
    (RO_FLAGS, "_COMM_PAGE_USER_PAGE_SHIFT_32", 0x024, "B", "VM page shift for 32-bit processes"),
    (
        RW_FLAGS,
        "_COMM_PAGE_USER_PAGE_SHIFT_64_LEGACY",
        0x025,
        "B",
        "VM page shift for 64-bit processes (legacy mapping)",
    ),
    (RO_FLAGS, "_COMM_PAGE_USER_PAGE_SHIFT_64", 0x025, "B", "VM page shift for 64-bit processes"),
    (RW_FLAGS, "_COMM_PAGE_CACHE_LINESIZE", 0x026, "H", "Cache line size"),
    (RW_FLAGS, "_COMM_PAGE_CPU_CLUSTERS", 0x02F, "B", "Number of CPU clusters"),
    (RW_FLAGS, "_COMM_PAGE_MEMORY_PRESSURE", 0x030, "I", "VM memory pressure"),
    (RW_FLAGS, "_COMM_PAGE_ACTIVE_CPUS", 0x034, "B", "Active CPUs"),
    (RW_FLAGS, "_COMM_PAGE_PHYSICAL_CPUS", 0x035, "B", "Physical CPUs"),
    (RW_FLAGS, "_COMM_PAGE_LOGICAL_CPUS", 0x036, "B", "Logical CPUs"),
    (
        RW_FLAGS,
        "_COMM_PAGE_KERNEL_PAGE_SHIFT_LEGACY",
        0x037,
        "B",
        "Kernel VM page shift (legacy mapping)",
    ),
    (RO_FLAGS, "_COMM_PAGE_KERNEL_PAGE_SHIFT", 0x037, "B", "Kernel VM page shift"),
    (RW_FLAGS, "_COMM_PAGE_MEMORY_SIZE", 0x038, "Q", "Maximum memory size"),
    (RW_FLAGS, "_COMM_PAGE_TIMEOFDAY_DATA", 0x040, "40s", "Legacy gettimeofday() data"),
    (RW_FLAGS, "_COMM_PAGE_CPUFAMILY", 0x080, "I", "CPU family identifier"),
    (RW_FLAGS, "_COMM_PAGE_DEV_FIRM_LEGACY", 0x084, "I", "Firmware debug handle (legacy mapping)"),
    (RO_FLAGS, "_COMM_PAGE_DEV_FIRM", 0x084, "I", "Firmware debug handle"),
    (
        RW_FLAGS,
        "_COMM_PAGE_TIMEBASE_OFFSET",
        0x088,
        "Q",
        "Timebase offset for mach_absolute_time()",
    ),
    (RW_FLAGS, "_COMM_PAGE_USER_TIMEBASE", 0x090, "B", "Userspace mach_absolute_time supported"),
    (RW_FLAGS, "_COMM_PAGE_CONT_HWCLOCK", 0x091, "B", "Continuous hardware clock present"),
    (RW_FLAGS, "_COMM_PAGE_DTRACE_DOF_ENABLED", 0x092, "B", "DTrace DOF enabled"),
    (RW_FLAGS, "_COMM_PAGE_CONT_TIMEBASE", 0x098, "Q", "Base for mach_continuous_time()"),
    (RW_FLAGS, "_COMM_PAGE_BOOTTIME_USEC", 0x0A0, "Q", "System boottime (usec)"),
    (RW_FLAGS, "_COMM_PAGE_CONT_HW_TIMEBASE", 0x0A8, "Q", "HW base for mach_continuous_time()"),
    (RW_FLAGS, "_COMM_PAGE_APPROX_TIME", 0x0C0, "Q", "Last known mach_absolute_time()"),
    (RW_FLAGS, "_COMM_PAGE_APPROX_TIME_SUPPORTED", 0x0C8, "B", "mach_approximate_time supported"),
    (RW_FLAGS, "_COMM_PAGE_KDEBUG_ENABLE", 0x100, "I", "Exported kdebug status bits"),
    (RW_FLAGS, "_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG", 0x104, "I", "ATM diagnostic config"),
    (RW_FLAGS, "_COMM_PAGE_MULTIUSER_CONFIG", 0x108, "I", "Multiuser config"),
    (RW_FLAGS, "_COMM_PAGE_NEWTIMEOFDAY_DATA", 0x120, "40s", "New gettimeofday() struct"),
    (RW_FLAGS, "_COMM_PAGE_REMOTETIME_PARAMS", 0x148, "24s", "Remote time bridge params"),
    (RW_FLAGS, "_COMM_PAGE_DYLD_FLAGS", 0x160, "Q", "Exported dyld_system_flags"),
    (RW_FLAGS, "_COMM_PAGE_CPU_QUIESCENT_COUNTER", 0x180, "Q", "CPU quiescent counter"),
    (RW_FLAGS, "_COMM_PAGE_CPU_TO_CLUSTER", 0x200, "256s", "CPU → cluster mapping table"),
    (RW_FLAGS, "_COMM_PAGE_ASB_TARGET_VALUE", 0x320, "Q", "Apple Security Bounty: random value"),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_ADDRESS",
        0x328,
        "Q",
        "Apple Security Bounty: random target address",
    ),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_KERN_VALUE",
        0x330,
        "Q",
        "Apple Security Bounty: random kernel value",
    ),
    (
        RW_FLAGS,
        "_COMM_PAGE_ASB_TARGET_KERN_ADDR",
        0x338,
        "Q",
        "Apple Security Bounty: random kernel address",
    ),
    (RW_FLAGS, "_COMM_PAGE_APT_MSG_POLICY", 0x340, "B", "APT_MSG policy"),
    (RW_FLAGS, "_COMM_PAGE_APT_ACTIVE", 0x341, "B", "APT active status"),
)

comm_fields = {
    "i386": FIELDS_X86,
    "x86-64": FIELDS_X86,
    "arm": FIELDS_ARM,
    "aarch64": FIELDS_ARM,
}

comm_start_page_rw = {
    "i386": 0xFFFF0000,
    "x86-64": 0x00007FFFFFE00000,
    "arm": 0xFFFF4000,
    "aarch64": 0x0000000FFFFFC000,
}

comm_start_page_ro = {
    "arm": 0xFFFFC000,
    "aarch64": 0x0000000FFFFF4000,
}

parser = argparse.ArgumentParser(description="Dumpuje wszystkie wartości z macOS commpage.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones."
)
from rich.console import Console
from rich.table import Table

@pwndbg.commands.Command(parser, category=CommandCategory.DARWIN)
def commpage(verbose: bool = False):
    table = Table(title="Commpage Dump")

    # kolumny
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Address", style="magenta", no_wrap=True)
    table.add_column("Value", style="green")
    if verbose:
        table.add_column("Description", style="yellow", overflow="fold")  # fold = zawijanie

    for flags, name, offset, fmt, desc in comm_fields[pwndbg.aglib.arch.name]:
        if flags == RO_FLAGS:
            page_start = comm_start_page_ro[pwndbg.aglib.arch.name]
        else:
            page_start = comm_start_page_rw[pwndbg.aglib.arch.name]

        addr = page_start + offset
        size = struct.calcsize(fmt)
        try:
            data = pwndbg.aglib.memory.read(addr, size)
            val = struct.unpack(fmt, data)[0]
            if isinstance(val, bytes):
                val = val.hex()
        except pwndbg.dbg_mod.Error as e:
            val = f"<cannot read> ({e})"

        if verbose:
            table.add_row(name, hex(addr), str(val), desc)
        else:
            table.add_row(name, hex(addr), str(val))

    Console().print(table)
