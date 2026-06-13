"""
Determine whether the target is being run under QEMU.
"""

from __future__ import annotations

import contextlib
import os
import random
import string
import subprocess
import tempfile
from typing import TYPE_CHECKING

from pt.machine import Machine

import pwndbg
import pwndbg.aglib
import pwndbg.lib.cache
import pwndbg.lib.qemu
from pwndbg.color import message

if TYPE_CHECKING:
    import pwndbg.aglib.kernel


@pwndbg.lib.cache.cache_until("stop")
def qemu_gdbserver_version() -> tuple[int, ...] | None:
    """
    Returns QEMU version. Works since QEMU 10.1.0
    """
    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.is_remote():
        return None

    response = inferior.send_remote("qGDBServerVersion")
    return pwndbg.lib.qemu.parse_qgdbserverversion(response)


@pwndbg.lib.cache.cache_until("stop")
def is_qemu() -> bool:
    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.is_remote():
        return False

    # Examples:
    #
    # pwndbg> maintenance packet Qqemu.sstepbits
    # sending: "Qqemu.sstepbits"
    # received: "ENABLE=1,NOIRQ=2,NOTIMER=4"
    #
    # pwndbg-lldb> process plugin packet send Qqemu.sstepbits
    #   packet: Qqemu.sstepbits
    # response: ENABLE=1,NOIRQ=2,NOTIMER=4
    #
    response = inferior.send_remote("Qqemu.sstepbits")

    return b"ENABLE=" in response


@pwndbg.lib.cache.cache_until("stop")
def is_usermode() -> bool:
    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.is_remote():
        return False

    # There is also 'qAttached' - maybe we can use it too?
    # for qemu user though it returned "0"?
    # Try with:
    #    qemu-x86_64 -g 1234 `which ps`
    #    gdb -nx `which ps` -ex 'target remote :1234'
    response = inferior.send_remote("qOffsets")

    return b"Text=" in response


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_usermode() -> bool:
    """Returns ``True`` if the target remote is being run under
    QEMU usermode emulation."""

    return is_qemu() and is_usermode()


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_kernel() -> bool:
    return is_qemu() and not is_usermode()


def is_old_qemu_user() -> bool:
    # qemu-user <8.1
    return is_qemu_usermode() and not exec_file_supported()


@pwndbg.lib.cache.cache_until("stop")
def exec_file_supported() -> bool:
    """Returns ``True`` if the remote target understands the 'qXfer:exec-file:read' packet.
    A check for this feature is done in vmmap code, to warn against running legacy Qemu versions.
    """
    response = pwndbg.dbg.selected_inferior().send_remote("qSupported")

    return b"qXfer:exec-file:read" in response


class QemuPhysAddressNotResolvedError(Exception):
    def __init__(self, address: int) -> None:
        super().__init__(
            f"Qemu physical address {hex(address)} cannot be resolved to a host virtual address"
        )


class QemuMtree:
    def __init__(self) -> None:
        self.mtree = []
        found_system = False
        """
        example `monitor info mtree -f` output:

        FlatView #2
        AS "memory", root: system
        AS "cpu-memory-0", root: system
        AS "cpu-memory-1", root: system
        AS "piix3-ide", root: bus master container
        AS "e1000", root: bus master container
        Root memory region: system
        0000000000000000-000000000009ffff (prio 0, ram): m0
        00000000000a0000-00000000000bffff (prio 1, i/o): vga-lowmem
        00000000000c0000-00000000000cafff (prio 0, rom): m0 @00000000000c0000
        00000000000cb000-00000000000cdfff (prio 0, ram): m0 @00000000000cb000
        00000000000ce000-00000000000e3fff (prio 0, rom): m0 @00000000000ce000
        00000000000e4000-00000000000effff (prio 0, ram): m0 @00000000000e4000
        00000000000f0000-00000000000fffff (prio 0, rom): m0 @00000000000f0000
        0000000000100000-000000007fffffff (prio 0, ram): m0 @0000000000100000
        0000000080000000-00000000bfffffff (prio 0, ram): m1
        00000000fd000000-00000000fdffffff (prio 1, ram): vga.vram
        00000000feb80000-00000000feb9ffff (prio 1, i/o): e1000-mmio
        00000000febb0000-00000000febb017f (prio 0, i/o): edid
        00000000febb0180-00000000febb03ff (prio 1, i/o): vga.mmio @0000000000000180
        00000000febb0400-00000000febb041f (prio 0, i/o): vga ioports remapped
        00000000febb0420-00000000febb04ff (prio 1, i/o): vga.mmio @0000000000000420
        00000000febb0500-00000000febb0515 (prio 0, i/o): bochs dispi interface
        00000000febb0516-00000000febb05ff (prio 1, i/o): vga.mmio @0000000000000516
        00000000febb0600-00000000febb0607 (prio 0, i/o): qemu extended regs
        00000000febb0608-00000000febb0fff (prio 1, i/o): vga.mmio @0000000000000608
        00000000fec00000-00000000fec00fff (prio 0, i/o): ioapic
        00000000fed00000-00000000fed003ff (prio 0, i/o): hpet
        00000000fee00000-00000000feefffff (prio 4096, i/o): apic-msi
        00000000fffc0000-00000000ffffffff (prio 0, rom): pc.bios
        0000000100000000-000000013fffffff (prio 0, ram): m1 @0000000040000000
        """
        for line in pwndbg.dbg.selected_inferior().send_monitor("info mtree -f").splitlines():
            line = line.strip()
            if "Root memory region: system" in line:
                found_system = True
                continue
            if found_system:
                if len(line) == 0:
                    break
                if ", ram):" not in line and ", rom):" not in line:
                    # gpa2hva would return: Memory at address 0xfeb80000is not RAM
                    continue
                phys_range = list(filter(None, line.split(" ")))[0]
                start, end = phys_range.split("-")
                start = int(start, 16)
                end = int(end, 16)
                res = pwndbg.dbg.selected_inferior().send_monitor(f"gpa2hva {hex(start)}")
                try:
                    hva = int(res.split(" ")[-1], 16)
                    self.mtree.append((start, end, hva))
                except Exception as e:
                    raise OSError(
                        f"Physical address {hex(start)} is not accessible. Reason: {e}. gpa2hva result: {res}"
                    )

    def find(self, physical_address: int) -> tuple[int, int]:
        for start, end, hva in self.mtree:
            if start <= physical_address <= end:
                return start, hva
        raise QemuPhysAddressNotResolvedError(physical_address)


# Most of QemuMachine code was inherited from gdb-pt-dump thanks to Martin Radev (@martinradev)
# on the MIT license, see:
# https://github.com/martinradev/gdb-pt-dump/blob/21158ac3f9b36d0e5e0c86193e0ef018fc628e74/pt_gdb/pt_gdb.py#L11-L80
class QemuMachine(Machine):
    def __init__(self) -> None:
        super().__init__()
        self.file = None
        self.pid = QemuMachine.get_qemu_pid()
        self.file = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)
        self.mtree = QemuMtree()

    def __del__(self) -> None:
        if self.file is not None:
            with contextlib.suppress(OSError):
                os.close(self.file)

    @staticmethod
    def search_pids_for_file(pids: list[str], filename: str) -> str | None:
        for pid in pids:
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    if os.readlink(f"{fd_dir}/{fd}") == filename:
                        return pid
            except FileNotFoundError:
                # Either the process has gone or fds are changing, not our pid
                pass
            except PermissionError:
                # Evade processes owned by other users
                pass

        return None

    @staticmethod
    def get_qemu_pid() -> int:
        try:
            out = subprocess.check_output(["pgrep", "qemu-system"], encoding="utf8")
            pids = out.strip().split("\n")

            if len(pids) == 1:
                return int(pids[0], 10)
            # We add a chardev file backend (we dont add a fronted, so it doesn't affect
            # the guest). We can then look through proc to find which process has the file
            # open. This approach is agnostic to namespaces (pid, network and mount).
            chardev_id = (
                "pwndbg-pt-dump" + "-" + "".join(random.choices(string.ascii_letters, k=16))
            )
            with tempfile.NamedTemporaryFile() as tmpf:
                pwndbg.dbg.selected_inferior().send_monitor(
                    f"chardev-add file,id={chardev_id},path={tmpf.name}"
                )
                pid_found = QemuMachine.search_pids_for_file(pids, tmpf.name)
                pwndbg.dbg.selected_inferior().send_monitor(f"chardev-remove {chardev_id}")
            if pid_found:
                return int(pid_found, 10)
        except subprocess.CalledProcessError:
            # If no process with the name `qemu-system` is found, fallback to alternative methods,
            # as the binary name may vary (e.g., `qemu_system`).
            pass
        raise ProcessLookupError("Could not find qemu-system pid")

    def read_memory(self, address: int, length: int) -> bytearray:
        phys = None
        res = pwndbg.dbg.selected_inferior().send_monitor(f"gva2gpa {address}")
        with contextlib.suppress(Exception):
            phys = int(res.split(" ")[-1], 16)
        if phys is None:
            phys = pwndbg.aglib.kernel.pagewalk(address).phys
        if phys is None:
            raise OSError(f"Virtual address {address} cannot be resolved")
        return bytearray(self.read_physical_memory(phys, length))

    def read_physical_memory(self, physical_address: int, length: int) -> bytearray:
        """
        Assumes each RAM chunk (defined by each line of the mtree output) is virtually contiguous on the host side
        Assumes any changes to the mtree output does not change the gpa2hva computed earlier, verified as follows:
            used -S to compare the mtree output during bootloading and when kernel has finished initialization
        """
        # It's not possible to pread large sizes, so let's break the request
        # into a few smaller ones.
        region_start, hva = self.mtree.find(physical_address)
        max_block_size = 1024 * 1024 * 256
        data = bytearray()
        assert self.file
        for offset in range(0, length, max_block_size):
            length_to_read = min(length - offset, max_block_size)
            block = os.pread(
                self.file,
                length_to_read,
                hva + physical_address - region_start + offset,
            )
            data.extend(block)
        return data

    def read_register(self, register_name: str) -> int:
        register_name = register_name.removeprefix("$")

        return int(pwndbg.aglib.regs.read_reg(register_name))


@pwndbg.lib.cache.cache_until("forever")
def get_qemu_machine(verbose: bool = False) -> QemuMachine | None:
    try:
        machine_backend = QemuMachine()
    except PermissionError:
        if verbose:
            print(
                message.error(
                    "Permission error when attempting to parse page tables with gdb-pt-dump.\n"
                    "Either change the kernel-vmmap setting, re-run GDB as root, or disable "
                    "`ptrace_scope` (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`)"
                )
            )
        return None
    except ProcessLookupError:
        if verbose:
            print(
                message.error(
                    "Could not find the PID for process named `qemu-system`.\n"
                    "This might happen if pwndbg is running on a different machine than `qemu-system`,\n"
                    "or if the `qemu-system` binary has a different name."
                )
            )
        return None
    except OSError as e:
        if verbose:
            print(e)
        return None
    return machine_backend
