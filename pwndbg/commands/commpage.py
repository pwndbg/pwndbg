from __future__ import annotations

import argparse
import struct

import tabulate
from typing import NamedTuple, List, Tuple

import pwndbg
import pwndbg.aglib.memory
import pwndbg.commands
from pwndbg.commands import CommandCategory

RW_FLAGS = 4 | 2
RO_FLAGS = 4

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

class CommPageField(NamedTuple):
    flags: int
    ctype: str
    name: str
    offset: int
    desc: str
    fmt: str

    def is_undocumented(self):
        return "UNDOCUMENTED" in self.name

    def is_unused(self):
        return "UNUSED" in self.name

    def is_readonly(self):
        return self.flags == RO_FLAGS

    def real_addr(self) -> int:
        if self.is_readonly():
            page_start = comm_start_page_ro[pwndbg.aglib.arch.name]
        else:
            page_start = comm_start_page_rw[pwndbg.aglib.arch.name]
        return page_start + self.offset

    def real_size(self) -> int:
        return struct.calcsize(self.fmt)

    def unpack(self) -> Any:
        addr = self.real_addr()
        size = self.real_size()
        try:
            data = pwndbg.aglib.memory.read(addr, size)
            val = struct.unpack(self.fmt, data)[0]
            # if isinstance(val, bytes):
            #     val = val.hex()
        except pwndbg.dbg_mod.Error as e:
            val = f"<cannot read> ({e})"
        return val


fields_arm = [
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_SIGNATURE", 0x000, "First few bytes contain a signature", "16s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CPU_CAPABILITIES64", 0x010, "CPU capabilities (64-bit)", "Q"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_UNUSED", 0x018, "Unused bytes", "6s"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_VERSION", 0x01E, "16-bit version number", "H"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_CPU_CAPABILITIES", 0x020, "CPU capabilities (32-bit)", "H"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_NCPUS", 0x022, "Number of configured CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_USER_PAGE_SHIFT_32_LEGACY", 0x024, "VM page shift for 32-bit processes (legacy)", "B"),
    CommPageField(RO_FLAGS, "uint8", "_COMM_PAGE_USER_PAGE_SHIFT_32", 0x024, "VM page shift for 32-bit processes", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_USER_PAGE_SHIFT_64_LEGACY", 0x025, "VM page shift for 64-bit processes (legacy)", "B"),
    CommPageField(RO_FLAGS, "uint8", "_COMM_PAGE_USER_PAGE_SHIFT_64", 0x025, "VM page shift for 64-bit processes", "B"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_CACHE_LINESIZE", 0x026, "Cache line size", "H"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_UNUSED4", 0x028, "Unused (was scheduler generation number)", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_UNUSED3", 0x02C, "Unused (was max spin count for mutexes)", "I"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_CPU_CLUSTERS", 0x02F, "Number of CPU clusters", "B"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_MEMORY_PRESSURE", 0x030, "Copy of VM memory pressure", "I"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_ACTIVE_CPUS", 0x034, "Number of active CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_PHYSICAL_CPUS", 0x035, "Number of physical CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_LOGICAL_CPUS", 0x036, "Number of logical CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_KERNEL_PAGE_SHIFT_LEGACY", 0x037, "Kernel VM page shift (legacy)", "B"),
    CommPageField(RO_FLAGS, "uint8", "_COMM_PAGE_KERNEL_PAGE_SHIFT", 0x037, "Kernel VM page shift", "B"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_MEMORY_SIZE", 0x038, "Maximum memory size", "Q"),
    CommPageField(RW_FLAGS, "struct commpage_timeofday_data_t", "_COMM_PAGE_TIMEOFDAY_DATA", 0x040, "Time-of-day data, gettimeofday() (legacy, 40 bytes)", "40s"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_CPUFAMILY", 0x080, "CPU family used by memcpy() resolver", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_DEV_FIRM_LEGACY", 0x084, "handle on PE_i_can_has_debugger (legacy)", "I"),
    CommPageField(RO_FLAGS, "uint32", "_COMM_PAGE_DEV_FIRM", 0x084, "handle on PE_i_can_has_debugger", "I"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_TIMEBASE_OFFSET", 0x088, "Timebase offset for mach_absolute_time()", "Q"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_USER_TIMEBASE", 0x090, "Is userspace mach_absolute_time supported", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_CONT_HWCLOCK", 0x091, "Always-on hardware clock presence for mach_continuous_time()", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_DTRACE_DOF_ENABLED", 0x092, "DTrace DOF enable flag", "B"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_UNUSED0", 0x093, "Unused bytes", "5s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CONT_TIMEBASE", 0x098, "Base for mach_continuous_time() relative to mach_absolute_time()", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_BOOTTIME_USEC", 0x0A0, "boottime in microseconds", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CONT_HW_TIMEBASE", 0x0A8, "Base for mach_continuous_time() relative to hardware counter", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_APPROX_TIME", 0x0C0, "Last known mach_absolute_time()", "Q"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_APPROX_TIME_SUPPORTED", 0x0C8, "Is mach_approximate_time supported", "B"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_UNUSED1", 0x0D9, "Unused (padding to align cacheline)", "39s"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_KDEBUG_ENABLE", 0x100, "Kdebug status bits exported to userspace", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG", 0x104, "atm_diagnostic_config exported to userspace", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_MULTIUSER_CONFIG", 0x108, "multiuser_config exported to userspace", "I"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_CUSTOM1", 0x10c, "Is jit_write_protect_supported_np", "B"),
    CommPageField(RW_FLAGS, "struct new_commpage_timeofday_data_t", "_COMM_PAGE_NEWTIMEOFDAY_DATA", 0x120, "gettimeofday(), struct new_commpage_timeofday_data_t (40 bytes)", "40s"),
    CommPageField(RW_FLAGS, "struct bt_params", "_COMM_PAGE_REMOTETIME_PARAMS", 0x148, "mach_bridge_remote_time(), struct bt_params (24 bytes)", "24s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_DYLD_FLAGS", 0x160, "Dyld system flags kern.dyld_system_flags exported to userspace", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CPU_QUIESCENT_COUNTER", 0x180, "CPU quiescent counter", "Q"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_CUSTOM2", 0x188, "Unused CPU quiescent counter (120 bytes reserved)", "120s"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_CPU_TO_CLUSTER", 0x200, "CPU ID to cluster ID mappings (256 bytes reserved)", "256s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_VALUE", 0x320, "Random target value for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_ADDRESS", 0x328, "Random target address for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_KERN_VALUE", 0x330, "Random kernel value for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_KERN_ADDRESS", 0x338, "Random kernel target address for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_APT_MSG_POLICY", 0x340, "APT message policy APT_MSG", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_APT_ACTIVE", 0x341, "APT active status (infrequently mutated)", "B"),
]

fields_x86 = [
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_SIGNATURE", 0x000, "First 16 bytes contain a signature", "16s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CPU_CAPABILITIES64", 0x010, "CPU capabilities (64-bit)", "Q"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_UNUSED", 0x018, "Unused bytes", "6s"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_VERSION", 0x01E, "16-bit version number", "H"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_CPU_CAPABILITIES", 0x020, "CPU capabilities (32-bit, retained for compatibility)", "H"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_NCPUS", 0x022, "Number of configured CPUs (hw.logicalcpu at boot time)", "B"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_UNUSED0", 0x024, "Unused bytes (previously reserved for cpu_capabilities expansion)", "2s"),
    CommPageField(RW_FLAGS, "uint16", "_COMM_PAGE_CACHE_LINESIZE", 0x026, "Cache line size", "H"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_UNUSED4", 0x028, "Unused (was scheduler generation number)", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_MEMORY_PRESSURE", 0x02C, "Copy of VM memory pressure", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_UNUSED3", 0x030, "Unused (was max spin count for mutexes)", "I"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_ACTIVE_CPUS", 0x034, "Number of active CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_PHYSICAL_CPUS", 0x035, "Number of physical CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_LOGICAL_CPUS", 0x036, "Number of logical CPUs", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_CPU_CLUSTERS", 0x037, "Number of CPU clusters", "B"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_MEMORY_SIZE", 0x038, "Maximum memory size", "Q"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_CPUFAMILY", 0x040, "CPU family (hw.cpufamily, x86)", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_KDEBUG_ENABLE", 0x044, "Kdebug enable exported to userspace", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG", 0x048, "ATM diagnostic configuration exported to userspace", "I"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_DTRACE_DOF_ENABLED", 0x04C, "DTrace DOF enable flag", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_KERNEL_PAGE_SHIFT", 0x04D, "Kernel VM page shift (version >=14)", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_USER_PAGE_SHIFT_64", 0x04E, "User VM page shift (version >=14)", "B"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_UNUSED2", 0x04F, "Unused", "B"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_TIME_DATA_START", 0x050, "Base for time-related offsets", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_NT_TSC_BASE", 0x050, "Nanotime TSC base", "Q"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_NT_SCALE", 0x058, "Nanotime scale", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_NT_SHIFT", 0x05C, "Nanotime shift", "I"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_NT_NS_BASE", 0x060, "Nanotime nanosecond base", "Q"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_NT_GENERATION", 0x068, "Nanotime generation counter", "I"),
    CommPageField(RW_FLAGS, "uint32", "_COMM_PAGE_GTOD_GENERATION", 0x06C, "Gettimeofday generation counter", "I"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_GTOD_NS_BASE", 0x070, "Gettimeofday nanosecond base", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_GTOD_SEC_BASE", 0x078, "Gettimeofday second base", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_APPROX_TIME", 0x080, "Used by mach_approximate_time()", "Q"),
    CommPageField(RW_FLAGS, "uint8", "_COMM_PAGE_APPROX_TIME_SUPPORTED", 0x088, "Flag if mach_approximate_time() is supported", "B"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_CONT_TIMEBASE", 0x0C0, "Base for mach_continuous_time()", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_BOOTTIME_USEC", 0x0C8, "Boot time in microseconds", "Q"),
    CommPageField(RW_FLAGS, "struct new_commpage_timeofday_data_t", "_COMM_PAGE_NEWTIMEOFDAY_DATA", 0x0D0, "New time-of-day data (40 bytes)", "40s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_DYLD_FLAGS", 0x100, "Dyld system flags exported to userspace", "Q"),
    CommPageField(RW_FLAGS, "?", "_COMM_PAGE_CPU_TO_CLUSTER", 0x108, "CPU ID to cluster ID mappings (256 bytes reserved)", "256s"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_VALUE", 0x320, "Random target value for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_ADDRESS", 0x328, "Random target address for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_KERN_VALUE", 0x330, "Random kernel value for security bounty", "Q"),
    CommPageField(RW_FLAGS, "uint64", "_COMM_PAGE_ASB_TARGET_KERN_ADDRESS", 0x338, "Random kernel target address for security bounty", "Q"),
]

def comm_fix_gaps(fields: List[CommPageField]) -> List[CommPageField]:
    fixed_fields = []
    prev_endaddr = 0
    for comm in fields:
        if comm.is_readonly():
            fixed_fields.append(comm)
            continue

        curr_addr = comm.offset
        if (gap_size := (curr_addr - prev_endaddr)) > 0:
            gap_addr = prev_endaddr
            fixed_fields.append(CommPageField(RW_FLAGS, f"? uint{gap_size * 8}", "GAP UNDOCUMENTED", gap_addr, "", f"{gap_size}s"))

        fixed_fields.append(comm)
        prev_endaddr = curr_addr + comm.real_size()

    max_comm_offset = 0xfff
    if (gap_size := (0xfff - prev_endaddr)) > 0:
        gap_addr = prev_endaddr
        fixed_fields.append(CommPageField(RW_FLAGS, f"? uint{gap_size * 8}", "GAP UNDOCUMENTED", gap_addr, "", f"{gap_size}s"))

    return fixed_fields


comm_fields = {
    "i386": comm_fix_gaps(fields_x86),
    "x86-64": comm_fix_gaps(fields_x86),
    "arm": comm_fix_gaps(fields_arm),
    "aarch64": comm_fix_gaps(fields_arm),
}


def pretty_bytes(data: bytes) -> str:
    if not data:
        return "b''"

    if len(set(data)) == 1 and len(data) > 1:
        return f"b'\\x{data[0]:02x}' <repeats {len(data)} times>"

    return repr(data)


parser = argparse.ArgumentParser(description="Dumpuje wszystkie wartości z macOS commpage.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones."
)
from rich.console import Console
from rich.table import Table

@pwndbg.commands.Command(parser, category=CommandCategory.DARWIN)
def commpage(verbose: bool = False):
    table = Table()

    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Address", style="magenta", no_wrap=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Value", style="green", overflow="fold")
    if verbose:
        table.add_column("Description", style="yellow", overflow="fold")

    for comm in comm_fields[pwndbg.aglib.arch.name]:
        val = comm.unpack()
        style = None
        if comm.is_undocumented():
            style = "red"
        if comm.is_unused():
            style = "yellow"

        if isinstance(val, bytes):
            val = pretty_bytes(val)
            if isinstance(val, bytes) and len(val) >= 1:
                val = repr(bytearray(val))

        rows = [comm.name, hex(comm.real_addr()), comm.ctype, str(val)]
        if verbose:
            rows.append(comm.desc)
        table.add_row(*rows, style=style)

    Console().print(table)
