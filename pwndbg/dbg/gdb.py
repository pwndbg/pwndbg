from __future__ import annotations

import re
from contextlib import nullcontext
from typing import Any
from typing import Coroutine
from typing import Generator
from typing import List
from typing import Literal
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import TypeVar

import gdb
from typing_extensions import Callable
from typing_extensions import Set
from typing_extensions import override

import pwndbg
import pwndbg.gdblib
import pwndbg.gdblib.events
import pwndbg.gdblib.remote
import pwndbg.lib.memory
from pwndbg.aglib import load_aglib
from pwndbg.dbg import selection
from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import load_gdblib
from pwndbg.lib.memory import PAGE_MASK
from pwndbg.lib.memory import PAGE_SIZE

T = TypeVar("T")


class GDBArch(pwndbg.dbg_mod.Arch):
    _endian: Literal["little", "big"]
    _name: str
    _ptrsize: int

    def __init__(self, endian: Literal["little", "big"], name: str, ptrsize: int):
        self._endian = endian
        self._name = name
        self._ptrsize = ptrsize

    @override
    @property
    def endian(self) -> Literal["little", "big"]:
        return self._endian

    @override
    @property
    def name(self) -> str:
        return self._name

    @override
    @property
    def ptrsize(self) -> int:
        return self._ptrsize


def parse_and_eval(expression: str, global_context: bool) -> gdb.Value:
    """
    Same as `gdb.parse_and_eval`, but only uses `global_context` if it is
    supported by the current version of GDB.

    `global_context` was introduced in GDB 14.
    """
    try:
        return gdb.parse_and_eval(expression, global_context)
    except TypeError:
        return gdb.parse_and_eval(expression)


class GDBRegisters(pwndbg.dbg_mod.Registers):
    def __init__(self, frame: GDBFrame):
        self.frame = frame

    @override
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        try:
            return GDBValue(self.frame.inner.read_register(name))
        except (gdb.error, ValueError):
            # GDB throws an exception if the name is unknown, we just return
            # None when that is the case.
            pass
        return None


class GDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: gdb.Frame):
        self.inner = inner

    @override
    def evaluate_expression(
        self, expression: str, lock_scheduler: bool = False
    ) -> pwndbg.dbg_mod.Value:
        from pwndbg.gdblib.scheduler import lock_scheduler as do_lock_scheduler

        with do_lock_scheduler() if lock_scheduler else nullcontext():
            with selection(self.inner, lambda: gdb.selected_frame(), lambda f: f.select()):
                try:
                    value = parse_and_eval(expression, global_context=False)
                except gdb.error as e:
                    raise pwndbg.dbg_mod.Error(e)

        return GDBValue(value)

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return GDBRegisters(self)

    @override
    def reg_write(self, name: str, val: int) -> bool:
        if name not in pwndbg.aglib.regs.all:
            return False

        with selection(self.inner, lambda: gdb.selected_frame(), lambda f: f.select()):
            try:
                gdb.execute(f"set ${name} = {val}")
                return True
            except gdb.error as e:
                raise pwndbg.dbg_mod.Error(e)

    @override
    def pc(self) -> int:
        return int(self.inner.pc())

    @override
    def sp(self) -> int:
        return int(self.regs().by_name("sp"))

    @override
    def parent(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            parent = self.inner.older()
            if parent is not None:
                return GDBFrame(parent)
        except (gdb.error, gdb.MemoryError) as e:
            # We can encounter a `gdb.error: PC not saved` here.
            raise pwndbg.dbg_mod.Error(e)

        return None

    @override
    def child(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            child = self.inner.newer()
            if child is not None:
                return GDBFrame(child)
        except (gdb.error, gdb.MemoryError) as e:
            # We can encounter a `gdb.error: PC not saved` here.
            raise pwndbg.dbg_mod.Error(e)

        return None

    @override
    def sal(self) -> Tuple[str, int] | None:
        sal = self.inner.find_sal()  # gdb.Symtab_and_line
        if sal.symtab is None:
            return None

        return sal.symtab.fullname(), sal.line

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, GDBFrame), "tried to compare GDBFrame to other type"
        other: GDBFrame = rhs

        return self.inner == other.inner


class GDBThread(pwndbg.dbg_mod.Thread):
    def __init__(self, inner: gdb.InferiorThread):
        self.inner = inner

    @override
    def bottom_frame(self) -> pwndbg.dbg_mod.Frame:
        with selection(self.inner, lambda: gdb.selected_thread(), lambda t: t.switch()):
            value = gdb.newest_frame()
        return GDBFrame(value)

    @override
    def ptid(self) -> int | None:
        _, lwpid, _ = self.inner.ptid
        return lwpid

    @override
    def index(self) -> int:
        return self.inner.num


class GDBMemoryMap(pwndbg.dbg_mod.MemoryMap):
    def __init__(self, reliable_perms: bool, qemu: bool, pages: Sequence[pwndbg.lib.memory.Page]):
        self.reliable_perms = reliable_perms
        self.qemu = qemu
        self.pages = pages

    @override
    def is_qemu(self) -> bool:
        return self.qemu

    @override
    def has_reliable_perms(self) -> bool:
        return self.reliable_perms

    @override
    def ranges(self) -> Sequence[pwndbg.lib.memory.Page]:
        return self.pages


# While this implementation allows breakpoints to be deleted, enabled and
# disabled from inside the code in a stop handler, GDB does not[1]. Aditionally,
# it behaves largely unpredictably when we try to do it. So, in order to allow
# for these things, we defer the operations on the GDB side until we're sure
# we can do them, and do some extra work on the Pwndbg side.
#
# [1]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html#Breakpoints-In-Python
BPWP_DEFERRED_DELETE: Set[GDBStopPoint] = set()
BPWP_DEFERRED_ENABLE: Set[GDBStopPoint] = set()
BPWP_DEFERRED_DISABLE: Set[GDBStopPoint] = set()


@pwndbg.gdblib.events.stop
def _bpwp_process_deferred():
    for to_enable in BPWP_DEFERRED_ENABLE:
        to_enable.inner.enabled = True
    for to_disable in BPWP_DEFERRED_DISABLE:
        to_disable.inner.enabled = False
    for to_delete in BPWP_DEFERRED_DELETE:
        to_delete.inner.delete()
    _bpwp_clear_deferred()


@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.exit
def _bpwp_clear_deferred():
    for elem in BPWP_DEFERRED_DELETE:
        elem._clear()
    for elem in BPWP_DEFERRED_ENABLE:
        elem._clear()
    for elem in BPWP_DEFERRED_DISABLE:
        elem._clear()

    BPWP_DEFERRED_DELETE.clear()
    BPWP_DEFERRED_ENABLE.clear()
    BPWP_DEFERRED_DISABLE.clear()


class BreakpointAdapter(gdb.Breakpoint):
    stop_handler: Callable[[], bool]

    @override
    def stop(self) -> bool:
        return self.stop_handler()


class GDBStopPoint(pwndbg.dbg_mod.StopPoint):
    inner: gdb.Breakpoint
    proc: GDBProcess
    inner_stop: Callable[[], bool] | None

    def __init__(self, inner: gdb.Breakpoint, proc: GDBProcess):
        self.inner = inner
        self.proc = proc
        self.inner_stop = None

    def _stop(self):
        """
        This function implements the same protocol as the GDB stop() function
        and may be slotted in place of the original function in case we need to
        disable or delete a breakpoint or watchpoint during the handling of
        a stop function.
        """
        if self not in BPWP_DEFERRED_DISABLE and self not in BPWP_DEFERRED_DELETE:
            return self.inner_stop()
        else:
            return False

    def _clear(self):
        """
        Removes the soft-disable aware handler and restores the original handler,
        if one was installed.
        """
        if self.inner_stop is not None:
            self.inner.stop = self.inner_stop
            self.inner_stop = None

    @override
    def set_enabled(self, enabled: bool) -> None:
        if self.proc.in_bpwp_stop_handler:
            # We're doing this during a stop handle. Change the stop function
            # in the breakpoint for the version that supports soft-disabling of
            # the breakpoint and then soft-disable it.
            self.inner_stop = self.inner.stop
            self.inner.stop = self._stop

            if enabled:
                target = BPWP_DEFERRED_ENABLE
                other = BPWP_DEFERRED_DISABLE
            else:
                target = BPWP_DEFERRED_DISABLE
                other = BPWP_DEFERRED_ENABLE
            if self in other:
                other.remove(self)

            target.add(self)
        else:
            # We're not in the middle of a stop handle, just enable or disable
            # it directly in GDB.
            self.inner.enabled = enabled

    @override
    def remove(self) -> None:
        if self.proc.in_bpwp_stop_handler:
            # Same as in `set_enabled`. We can't actually disable it right away,
            # but we can stop the handle from running and prevent the breakpoint
            # from stopping the program until it actually gets deleted.
            self.inner_stop = self.inner.stop
            self.inner.stop = self._stop
            BPWP_DEFERRED_DELETE.add(self)
        else:
            self.inner.delete()


class GDBProcess(pwndbg.dbg_mod.Process):
    # Operations that change the internal state of GDB are generally not allowed
    # during breakpoint stop handles. Because the Pwndbg Debugger-agnostic API
    # generally does not have this limitation, we keep track of these handles,
    # in order to properly block off or implement operations we support, but
    # that GDB would misbehave doing.
    in_bpwp_stop_handler: bool

    def __init__(self, inner: gdb.Inferior):
        self.inner = inner
        self.in_bpwp_stop_handler = False

    @override
    def threads(self) -> List[pwndbg.dbg_mod.Thread]:
        return [GDBThread(thread) for thread in gdb.selected_inferior().threads()]

    @override
    def pid(self) -> int | None:
        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return None

    @override
    def alive(self) -> bool:
        return gdb.selected_thread() is not None

    @override
    def stopped_with_signal(self) -> bool:
        return "It stopped with signal " in gdb.execute("info program", to_string=True)

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(parse_and_eval(expression, global_context=True))
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def vmmap(self) -> pwndbg.dbg_mod.MemoryMap:
        import pwndbg.gdblib.vmmap
        from pwndbg.gdblib import gdb_version

        pages = pwndbg.gdblib.vmmap.get()
        qemu = pwndbg.gdblib.qemu.is_qemu() and not pwndbg.gdblib.qemu.exec_file_supported()

        # Only GDB versions >=12 report permission info in info proc mappings.
        # On older versions, we fallback on "rwx".
        # See https://github.com/bminor/binutils-gdb/commit/29ef4c0699e1b46d41ade00ae07a54f979ea21cc
        reliable_perms = not (pwndbg.gdblib.qemu.is_qemu_usermode() and gdb_version[0] < 12)

        return GDBMemoryMap(reliable_perms, qemu, pages)

    @override
    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        result = b""
        count = max(int(size), 0)
        addr = address

        try:
            result = gdb.selected_inferior().read_memory(addr, count)
        except gdb.error as e:
            if not partial:
                raise pwndbg.dbg_mod.Error(e)

            message = str(e)

            stop_addr = addr
            match = re.search(r"Memory at address (\w+) unavailable\.", message)
            if match:
                stop_addr = int(match.group(1), 0)
            else:
                stop_addr = int(message.split()[-1], 0)

            if stop_addr != addr:
                return self.read_memory(addr, stop_addr - addr)

            # QEMU will return the start address as the failed
            # read address.  Try moving back a few pages at a time.
            stop_addr = addr + count

            # Move the stop address down to the previous page boundary
            stop_addr &= PAGE_MASK
            while stop_addr > addr:
                result = self.read_memory(addr, stop_addr - addr)

                if result:
                    return bytearray(result)

                # Move down by another page
                stop_addr -= PAGE_SIZE

        return bytearray(result)

    @override
    def write_memory(self, address: int, data: bytearray, partial: bool = False) -> int:
        try:
            # Throws an exception if can't access memory
            gdb.selected_inferior().write_memory(address, data)
        except gdb.MemoryError as e:
            if partial:
                raise NotImplementedError("partial writes are currently not supported under gdb")

            raise pwndbg.dbg_mod.Error(e)
        return len(data)

    @override
    def find_in_memory(
        self,
        pattern: bytearray,
        start: int,
        size: int,
        align: int,
        max_matches: int = -1,
        step: int = -1,
    ) -> Generator[int, None, None]:
        if max_matches == 0 or len(pattern) == 0:
            # Nothing to match.
            return

        i = gdb.selected_inferior()
        end = start + size
        limit = None if max_matches < 0 else max_matches
        found_count = 0

        while True:
            # No point in searching if we can't read the memory
            try:
                i.read_memory(start, 1)
            except gdb.MemoryError:
                break

            length = end - start
            if length <= 0:
                break

            try:
                start = i.search_memory(start, length, pattern)
            except gdb.error as e:
                # While remote debugging on an embedded device and searching
                # through a large memory region (~512mb), gdb may return an error similar
                # to `error: Invalid hex digit 116`, even though the search
                # itself is ok. It seems to have to do with a timeout.
                print(f"WARN: gdb.search_memory failed with: {e}")
                if e.args[0].startswith("Invalid hex digit"):
                    print(
                        "WARN: This is possibly related to a timeout. Connection is likely broken."
                    )
                    break
                start = None
                pass

            if start is None:
                break

            # Fix bug: In kernel mode, search_memory may return a negative address,
            # e.g. -1073733344, which supposed to be 0xffffffffc0002120 in kernel.
            start &= 0xFFFFFFFFFFFFFFFF

            # Ignore results that don't match required alignment
            if start & (align - 1):
                start = pwndbg.lib.memory.round_up(start, align)
                continue

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            try:
                i.read_memory(start, 1)
            except gdb.MemoryError:
                break

            yield start
            found_count += 1
            if limit and found_count >= limit:
                break

            if step > 0:
                start = pwndbg.lib.memory.round_down(start, step) + step
            else:
                if align > 1:
                    start = pwndbg.lib.memory.round_up(start + len(pattern), align)
                else:
                    start += len(pattern)

    @override
    def is_remote(self) -> bool:
        return pwndbg.gdblib.remote.is_remote()

    @override
    def send_remote(self, packet: str) -> str:
        try:
            return gdb.execute(f"maintenance packet {packet}", to_string=True)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def send_monitor(self, cmd: str) -> str:
        try:
            return gdb.execute(f"monitor {cmd}", to_string=True)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def download_remote_file(self, remote_path: str, local_path: str) -> None:
        try:
            error = gdb.execute(f'remote get "{remote_path}" "{local_path}"', to_string=True)
        except gdb.error as e:
            error = str(e)

        if error:
            # If the client is configured with set debug remote 1, we need to
            # skip [remote] lines, and not interpret as missing file. Maybe
            # better to search for error strings. A real error will say:
            # "Remote I/O error: No such file or directory"
            real_error = []
            for line in error.splitlines():
                if not line.startswith("[remote]"):
                    real_error.append(line)
            if len(real_error):
                error = "\n".join(real_error)
                raise pwndbg.dbg_mod.Error(
                    "Could not download remote file %r:\nError: %s" % (remote_path, error)
                )

    # Note that in GDB this method does not depend on the process at all!
    #
    # From the point-of-view of the GDB implementation, this could very well be
    # implemented as part of Debugger. The issue with that, however, is that the
    # LLDB implementation would have to do some fairly heavy legwork to keep up
    # the appearance that values are independent from any given target.
    #
    # Opting instead to have this method be at this level, although slightly
    # redundant in GDB, saves a ton of work in LLDB.
    @override
    def create_value(
        self, value: int, type: pwndbg.dbg_mod.Type | None = None
    ) -> pwndbg.dbg_mod.Value:
        v = GDBValue(gdb.Value(value))
        if type:
            v = v.cast(type)

        return v

    @override
    def symbol_name_at_address(self, address: int) -> str | None:
        import pwndbg.gdblib.symbol

        return pwndbg.gdblib.symbol.get(address) or None

    @override
    def symbol_address_from_name(self, name: str, prefer_static: bool = False) -> int | None:
        import pwndbg.gdblib.symbol

        try:
            static = None
            if prefer_static:
                static = pwndbg.gdblib.symbol.static_linkage_symbol_address(name)
            return static or pwndbg.gdblib.symbol.address(name) or None
        except gdb.error:
            raise pwndbg.dbg_mod.Error()

    @override
    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        # In GDB, process-level lookups for types are always global.
        #
        # Additionally, the GDB type lookup function only ever returns the first
        # match, so this will always return a list with one element.
        try:
            return [GDBType(gdb.lookup_type(name))]
        except gdb.error:
            return []

    @override
    def arch(self) -> pwndbg.dbg_mod.Arch:
        ptrsize = pwndbg.aglib.typeinfo.ptrsize
        not_exactly_arch = False

        endian: Literal["little", "big"] = None
        if "little" in gdb.execute("show endian", to_string=True).lower():
            endian = "little"
        else:
            endian = "big"

        if pwndbg.aglib.proc.alive:
            arch = gdb.newest_frame().architecture().name()
        else:
            arch = gdb.execute("show architecture", to_string=True).strip()
            not_exactly_arch = True

        # Below, we fix the fetched architecture
        for match in pwndbg.aglib.arch_mod.ARCHS:
            if match in arch:
                # Distinguish between Cortex-M and other ARM
                # When GDB detects correctly Cortex-M processes, it will label them with `arm*-m`, such as armv7e-m
                # However, GDB will sometimes fail to correctly label Cortex-M binaries properly, and says it's simply 'arm'.
                # Internally, GDB still detects the processes as Cortex-M, as it can access .xpsr, but it doesn't
                # appear to expose this in information through any command/API. Since Cortex-M has the .xpsr flags register
                # instead of .cpsr, we will check if it's present.
                # See: https://github.com/pwndbg/pwndbg/issues/2153
                if match == "arm" and ("-m" in arch or pwndbg.aglib.regs.xpsr is not None):
                    match = "armcm"
                elif match.startswith("riscv:"):
                    match = match[6:]
                elif match == "riscv":
                    # If GDB doesn't detect the width, it will just say `riscv`.
                    match = "rv64"
                return GDBArch(endian, match, ptrsize)

        if not_exactly_arch:
            raise RuntimeError(f"Could not deduce architecture from: {arch}")

        return GDBArch(endian, arch, ptrsize)

    @override
    def break_at(
        self,
        location: pwndbg.dbg_mod.BreakpointLocation | pwndbg.dbg_mod.WatchpointLocation,
        stop_handler: Callable[[pwndbg.dbg_mod.StopPoint], bool] | None = None,
        one_shot: bool = False,
        internal: bool = False,
    ) -> pwndbg.dbg_mod.StopPoint:
        # GDB does not support creating new breakpoints in the middle of a
        # breakpoint stop handler[1]. Catch that case and throw an exception.
        #
        # [1]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html#Breakpoints-In-Python
        if self.in_bpwp_stop_handler:
            raise pwndbg.dbg_mod.Error(
                "Creating new Breakpoints/Watchpoints while in a stop handler is not allowed in GDB"
            )

        if isinstance(location, pwndbg.dbg_mod.BreakpointLocation):
            bp = BreakpointAdapter(
                f"*{location.address:#x}",
                gdb.BP_BREAKPOINT,
                internal=internal,
                temporary=one_shot,
            )
        elif isinstance(location, pwndbg.dbg_mod.WatchpointLocation):
            if location.watch_read and location.watch_write:
                c = gdb.WP_ACCESS
            elif location.watch_write:
                c = gdb.WP_WRITE
            elif location.watch_read:
                c = gdb.WP_READ

            bp = BreakpointAdapter(
                f"(char[{location.size}])*{location.address}",
                gdb.BP_WATCHPOINT,
                wp_class=c,
                internal=internal,
                temporary=one_shot,
            )

        if internal:
            bp.silent = True

        sp = GDBStopPoint(bp, self)

        if stop_handler is not None:

            def handler():
                self.in_bpwp_stop_handler = True
                stop = stop_handler(sp)
                self.in_bpwp_stop_handler = False
                return stop
        else:

            def handler():
                return True

        bp.stop_handler = handler

        return sp

    @override
    def is_linux(self) -> bool:
        # Detect current ABI of client side by 'show osabi'
        #
        # Examples of strings returned by `show osabi`:
        # 'The current OS ABI is "auto" (currently "GNU/Linux").\nThe default OS ABI is "GNU/Linux".\n'
        # 'The current OS ABI is "GNU/Linux".\nThe default OS ABI is "GNU/Linux".\n'
        # 'El actual SO ABI es «auto» (actualmente «GNU/Linux»).\nEl SO ABI predeterminado es «GNU/Linux».\n'
        # 'The current OS ABI is "auto" (currently "none")'
        #
        # As you can see, there might be GDBs with different language versions
        # and so we have to support it there too.
        # Lets assume and hope that `current osabi` is returned in first line in all languages...
        abi = gdb.execute("show osabi", to_string=True).split("\n")[0]

        # Currently we support those osabis:
        # 'GNU/Linux': linux
        # 'none': bare metal

        return "GNU/Linux" in abi

    @override
    def disasm(self, address: int) -> pwndbg.dbg_mod.DisassembledInstruction | None:
        # Currently the type returned by GDB here maps correctly to the type
        # returned by this function, so we don't have to do any extra work.
        #
        # That type is defined in
        # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Architectures-In-Python.html#Architectures-In-Python
        ins: pwndbg.dbg_mod.DisassembledInstruction = (
            gdb.newest_frame().architecture().disassemble(address)[0]
        )
        return ins

    @override
    def module_section_locations(self) -> List[Tuple[int, int, str, str]]:
        import pwndbg.gdblib.info

        # Example:
        #
        # 0x0000555555572f70 - 0x0000555555572f78 is .init_array
        # 0x0000555555572f78 - 0x0000555555572f80 is .fini_array
        # 0x0000555555572f80 - 0x0000555555573a78 is .data.rel.ro
        # 0x0000555555573a78 - 0x0000555555573c68 is .dynamic
        # 0x0000555555573c68 - 0x0000555555573ff8 is .got
        # 0x0000555555574000 - 0x0000555555574278 is .data
        # 0x0000555555574280 - 0x0000555555575540 is .bss
        # 0x00007ffff7fc92a8 - 0x00007ffff7fc92e8 is .note.gnu.property in /lib64/ld-linux-x86-64.so.2
        # 0x00007ffff7fc92e8 - 0x00007ffff7fc930c is .note.gnu.build-id in /lib64/ld-linux-x86-64.so.2
        # 0x00007ffff7fc9310 - 0x00007ffff7fc94f8 is .gnu.hash in /lib64/ld-linux-x86-64.so.2

        files = pwndbg.gdblib.info.files()

        main = self.main_module_name()
        result = []
        for line in files.splitlines():
            line = line.strip()
            if " - " not in line or " is " not in line:
                # Ignore non-location lines.
                continue

            div0 = line.split(" is ", 1)
            assert (
                len(div0) == 2
            ), "Wrong string format assumption while parsing the output of `info files`"

            div1 = div0[1].split(" in ", 1)
            assert (
                len(div1) == 1 or len(div1) == 2
            ), "Wrong string format assumption while parsing the output of `info files`"

            div2 = div0[0].split(" - ", 1)
            assert (
                len(div2) == 2
            ), "Wrong string format assumption while parsing the output of `info files`"

            beg = int(div2[0].strip(), 0)
            end = int(div2[1].strip(), 0)

            if len(div1) == 2:
                module = div1[1].strip()
            else:
                module = main

            section = div1[0].strip()

            result.append((beg, end - beg, section, module))

        return result

    @override
    def main_module_name(self) -> str | None:
        # Can GDB ever return a different value here from what we'd get with
        # `info files`, give or take a "remote:"?
        if not self.alive():
            return gdb.current_progspace().filename

        exe = gdb.execute("info proc exe", to_string=True)
        return exe[exe.find("exe = '") + 7 : exe.rfind("'")]

    @override
    def main_module_entry(self) -> int | None:
        import pwndbg.gdblib.info

        for line in pwndbg.gdblib.info.files().splitlines():
            if "Entry point" in line:
                entry_point = int(line.split()[-1], 16)

                # PIE entry points are sometimes reported as an
                # offset from the module base.
                if entry_point < 0x10000:
                    break

                return entry_point

        return None

    @override
    def is_dynamically_linked(self) -> bool:
        out = gdb.execute("info dll", to_string=True)
        return "No shared libraries loaded at this time." not in out

    @override
    def dispatch_execution_controller(
        self, procedure: Callable[[pwndbg.dbg_mod.ExecutionController], Coroutine[Any, Any, None]]
    ):
        # GDB isn't nearly as finnicky as LLDB when it comes to us controlling
        # the execution of the inferior, so we can safely mostly ignore all of
        # the async plumbing and drive the coroutine by just iterating over it.
        #
        # Aditionally, the Debugger-agnostic API allows us enough freedom in how
        # we schedule execution of the controller that running it immediately is
        # perfectly acceptable. So that's what we do.

        coroutine = procedure(EXECUTION_CONTROLLER)
        while True:
            try:
                # We don't need to bother communicating with the coroutine, as
                # it doesn't yield anything we care about.
                coroutine.send(None)
            except StopIteration:
                # We're done.
                break


class GDBExecutionController(pwndbg.dbg_mod.ExecutionController):
    @override
    async def single_step(self):
        gdb.execute("si")

    @override
    async def cont(self, until: pwndbg.dbg_mod.StopPoint):
        gdb.execute("continue")


# Like in LLDB, we only need a single instance of the execution controller.
EXECUTION_CONTROLLER = GDBExecutionController()


class GDBCommand(gdb.Command):
    def __init__(
        self,
        debugger: GDB,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
    ):
        self.debugger = debugger
        self.handler = handler
        self.__doc__ = doc
        super().__init__(name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

    def invoke(self, args: str, from_tty: bool) -> None:
        self.handler(self.debugger, args, from_tty)


class GDBCommandHandle(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, command: gdb.Command):
        self.command = command

    def remove(self) -> None:
        # GDB doesn't support command removal.
        pass


class GDBType(pwndbg.dbg_mod.Type):
    CODE_MAPPING = {
        gdb.TYPE_CODE_INT: pwndbg.dbg_mod.TypeCode.INT,
        gdb.TYPE_CODE_UNION: pwndbg.dbg_mod.TypeCode.UNION,
        gdb.TYPE_CODE_STRUCT: pwndbg.dbg_mod.TypeCode.STRUCT,
        gdb.TYPE_CODE_ENUM: pwndbg.dbg_mod.TypeCode.ENUM,
        gdb.TYPE_CODE_TYPEDEF: pwndbg.dbg_mod.TypeCode.TYPEDEF,
        gdb.TYPE_CODE_PTR: pwndbg.dbg_mod.TypeCode.POINTER,
        gdb.TYPE_CODE_ARRAY: pwndbg.dbg_mod.TypeCode.ARRAY,
    }

    def __init__(self, inner: gdb.Type):
        self.inner = inner

    @property
    @override
    def sizeof(self) -> int:
        return self.inner.sizeof

    @property
    @override
    def alignof(self) -> int:
        return self.inner.alignof

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        assert self.inner.code in GDBType.CODE_MAPPING, "missing mapping for type code"
        return GDBType.CODE_MAPPING[self.inner.code]

    @override
    def fields(self) -> List[pwndbg.dbg_mod.TypeField] | None:
        return [
            pwndbg.dbg_mod.TypeField(
                field.bitpos,
                field.name,
                GDBType(field.type),
                field.parent_type,
                field.enumval if hasattr(field, "enumval") else 0,
                field.artificial,
                field.is_base_class,
                field.bitsize,
            )
            for field in self.inner.fields()
        ]

    @override
    def has_field(self, name: str) -> bool:
        # For GDB, we can do a little better than the default implementation, as
        # it has a specific convenience function that checks for this condition
        # exactly.
        return gdb.types.has_field(self.inner, name)

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        # GDB's .array function expects the inclusive upper bound of the array,
        # not the number of elements.
        return GDBType(self.inner.array(count - 1))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.pointer())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.strip_typedefs())

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.target())

    @override
    def keys(self) -> List[str]:
        return list(self.inner.keys())


class GDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: gdb.Value):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        return GDBValue(self.inner.address)

    @property
    @override
    def is_optimized_out(self) -> bool:
        return self.inner.is_optimized_out

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        return GDBValue(self.inner.dereference())

    @override
    def string(self) -> str:
        return self.inner.string()

    @override
    def fetch_lazy(self) -> None:
        self.inner.fetch_lazy()

    @override
    def __int__(self) -> int:
        try:
            return int(self.inner)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        # We let the consumers of this function just pass it a `gdb.Type`.
        # This keeps us from breaking functionality under GDB until we have
        # better support for type lookup under LLDB and start porting the
        # commands that need this to the new API.
        #
        # FIXME: Remove sloppy `gdb.Type` exception in `GDBValue.cast()`
        if isinstance(type, gdb.Type):
            return GDBValue(self.inner.cast(type))

        assert isinstance(type, GDBType)
        t: GDBType = type

        try:
            return GDBValue(self.inner.cast(t.inner))
        except gdb.error as e:
            # GDB casts can fail.
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __add__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(self.inner + rhs)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __sub__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(self.inner - rhs)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __getitem__(self, key: str | int) -> pwndbg.dbg_mod.Value:
        if self.inner.type.code == gdb.TYPE_CODE_STRUCT and isinstance(key, int):
            # GDB doesn't normally support indexing fields in a struct by int,
            # so we nudge it a little.
            key = self.inner.type.fields()[key]

        return GDBValue(self.inner[key])


class GDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self):
        from pwndbg.commands import load_commands

        load_gdblib()
        load_aglib()
        load_commands()

        # Importing `pwndbg.gdblib.prompt` ends up importing code that has the
        # side effect of setting a command up. Because command setup requires
        # `pwndbg.dbg` to already be set, and this module is used as part of the
        # process of setting it, we have to wait, and do the import as part of
        # this method.
        from pwndbg.gdblib import prompt

        prompt.set_prompt()

        pre_commands = """
        set confirm off
        set verbose off
        set pagination off
        set history save on
        set follow-fork-mode child
        set backtrace past-main on
        set step-mode on
        set print pretty on
        handle SIGALRM nostop print nopass
        handle SIGBUS  stop   print nopass
        handle SIGPIPE nostop print nopass
        handle SIGSEGV stop   print nopass
        """.strip()

        # See https://github.com/pwndbg/pwndbg/issues/808
        if gdb_version[0] <= 9:
            pre_commands += "\nset remote search-memory-packet off"

        for line in pre_commands.strip().splitlines():
            gdb.execute(line)

        # This may throw an exception, see pwndbg/pwndbg#27
        try:
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            pass

        pwndbg.gdblib.tui.setup()

        # Reading Comment file
        from pwndbg.commands import comments

        comments.init()

        from pwndbg.gdblib import config_mod

        config_mod.init_params()

        prompt.show_hint()

    @override
    def add_command(
        self,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
    ) -> pwndbg.dbg_mod.CommandHandle:
        command = GDBCommand(self, name, handler, doc)
        return GDBCommandHandle(command)

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # GDB displays commands in groups of 10. We might want more than that,
        # so we fetch multiple blocks of 10 and assemble them into the final
        # history in a second step.
        parsed_blocks = []
        parsed_lines_count = 0
        parsed_lines_min = None
        parsed_lines_max = None
        parsed_lines_base = None

        while parsed_lines_count < last:
            # Fetch and parse the block we're currently interested in.
            base = f" {parsed_lines_base}" if parsed_lines_base else ""

            lines = gdb.execute(f"show commands{base}", from_tty=False, to_string=True)
            lines = lines.splitlines()

            parsed_lines = []
            for line in lines:
                try:
                    number_str, command = line.split(maxsplit=1)
                except ValueError:
                    # In rare cases GDB stores a number with no command, and the split()
                    # then only returns one element. We can safely ignore these.
                    continue

                try:
                    number = int(number_str)
                except ValueError:
                    # In rare cases GDB will output a warning after executing `show commands`
                    # (i.e. "warning: (Internal error: pc 0x0 in read in CU, but not in
                    # symtab.)").
                    return []

                parsed_lines.append((number, command))

            # We have nothing more to parse if GDB gives us nothing here.
            if len(parsed_lines) == 0:
                break

            # Set the maximum command index we know about. This is simply the
            # last element of the first block.
            if not parsed_lines_max:
                parsed_lines_max = parsed_lines[-1][0]

            # Keep track of the minimum command index we've seen.
            #
            # This is usually the first element in the most recent block, but
            # GDB isn't very clear about whether running commands with
            # `gdb.execute` affects the command history, and what the exact size
            # of the command history is. This means that, at the very end, the
            # first index in the last block might be one greater than the last
            # index in the second-to-last block.
            #
            # Additionally, the value of the first element being greater than
            # the minimum also means that we reached the end of the command
            # history on the last block, can break out of the loop early, and
            # don't even need to bother with this block.
            if parsed_lines_min:
                if parsed_lines[0][0] < parsed_lines_min:
                    parsed_lines_min = parsed_lines[0][0]
                else:
                    break
            else:
                parsed_lines_min = parsed_lines[0][0]

            parsed_blocks.append(parsed_lines)
            parsed_lines_count += len(parsed_lines)

            # If we've just pulled the block with command index 0, we know we
            # can't possibly go back any farther.
            if parsed_lines_base == 0:
                break

            # The way GDB displays the command history is _weird_. The argument
            # we pass to `show commands <arg>` is the index of the 6th element
            # in the block, meaning we'll get a block whose values range from
            # at most <arg> - 5 to at most <arg> + 4, inclusive.
            #
            # Given that we want the first element in this block to the just one
            # past the maximum range of the block returned by the next arguemnt,
            # and that we know the last element in a block is at most <arg> + 4,
            # we can subtract five from its index to land in the right spot.
            parsed_lines_base = max(0, parsed_lines[0][0] - 5)

        # We've got nothing.
        if len(parsed_blocks) == 0:
            return []

        # Sort the elements in the block into the final history array.
        remaining = parsed_lines_max - parsed_lines_min + 1
        plines: List[Tuple[int, str]] = [None] * remaining
        while remaining > 0 and len(parsed_blocks) > 0:
            block = parsed_blocks.pop()
            for pline in block:
                index = pline[0] - parsed_lines_min
                if not plines[index]:
                    plines[pline[0] - parsed_lines_min] = pline
                    remaining -= 1

        # If this fails, either some of our assumptions were wrong, or GDB is
        # doing something funky with the output, either way, not good.
        assert remaining == 0, "There are gaps in the command history"

        return plines[-last:]

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return gdb.string_to_argv(command_line)

    @override
    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        thread = gdb.selected_thread()
        if thread:
            return GDBThread(thread)
        return None

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            frame = gdb.selected_frame()
            if frame:
                return GDBFrame(frame)
        except gdb.error:
            pass
        return None

    def commands(self):
        current_pagination = gdb.execute("show pagination", to_string=True)
        current_pagination = current_pagination.split()[-1].rstrip(
            "."
        )  # Take last word and skip period

        gdb.execute("set pagination off")
        command_list = gdb.execute("help all", to_string=True).strip().split("\n")
        existing_commands: Set[str] = set()
        for line in command_list:
            line = line.strip()
            # Skip non-command entries
            if (
                not line
                or line.startswith("Command class:")
                or line.startswith("Unclassified commands")
            ):
                continue
            command = line.split()[0]
            existing_commands.add(command)
        gdb.execute(f"set pagination {current_pagination}")  # Restore original setting
        return existing_commands

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        return GDBProcess(gdb.selected_inferior())

    @override
    def is_gdblib_available(self):
        return True

    @override
    def has_event_type(self, ty: pwndbg.dbg_mod.EventType) -> bool:
        # Currently GDB supports all event types.
        return True

    @override
    def event_handler(
        self, ty: pwndbg.dbg_mod.EventType
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        # Make use of the existing gdblib event handlers.
        if ty == pwndbg.dbg_mod.EventType.EXIT:
            return pwndbg.gdblib.events.exit
        elif ty == pwndbg.dbg_mod.EventType.CONTINUE:
            return pwndbg.gdblib.events.cont
        elif ty == pwndbg.dbg_mod.EventType.START:
            return pwndbg.gdblib.events.start
        elif ty == pwndbg.dbg_mod.EventType.STOP:
            return pwndbg.gdblib.events.stop
        elif ty == pwndbg.dbg_mod.EventType.NEW_MODULE:
            return pwndbg.gdblib.events.new_objfile
        elif ty == pwndbg.dbg_mod.EventType.MEMORY_CHANGED:
            return pwndbg.gdblib.events.mem_changed
        elif ty == pwndbg.dbg_mod.EventType.REGISTER_CHANGED:
            return pwndbg.gdblib.events.reg_changed

    @override
    def set_sysroot(self, sysroot: str) -> bool:
        try:
            gdb.execute(f"set sysroot {sysroot}", from_tty=False)
            # Assume it worked..
            return True
        except gdb.error:
            return False

    @override
    def supports_breakpoint_creation_during_stop_handler(self) -> bool:
        return False

    @override
    def x86_disassembly_flavor(self) -> Literal["att", "intel"]:
        try:
            flavor = gdb.execute("show disassembly-flavor", to_string=True).lower().split('"')[1]
        except gdb.error as e:
            if str(e).find("disassembly-flavor") > -1:
                flavor = "intel"
            else:
                raise pwndbg.dbg_mod.Error(e)

        if flavor != "att" and flavor != "intel":
            raise pwndbg.dbg_mod.Error(f"unrecognized disassembly flavor '{flavor}'")

        literal: Literal["att", "intel"] = flavor
        return literal

    @override
    def string_limit(self) -> int:
        message = gdb.execute("show print elements", from_tty=False, to_string=True)
        message = message.split("\n")[0].split()[-1]
        message = message.strip(".")
        if message == "unlimited":
            return 0
        else:
            return int(message)

    @override
    def addrsz(self, address: Any) -> str:
        address = int(address) & pwndbg.aglib.arch.ptrmask
        return f"%#{2 * pwndbg.aglib.arch.ptrsize}x" % address

    @override
    def get_cmd_window_size(self) -> Tuple[Optional[int], Optional[int]]:
        """Get the size of the command window.

        GDB keeps these parameters up to date with the actual window size
        of the command output. This is the full terminal size in CLI mode
        or the size of the cmd window in TUI mode.

        When the window size is set to be unlimited (0), the parameter
        is None.
        """
        width = gdb.parameter("width")
        height = gdb.parameter("height")
        return (
            height if height is None else int(height),
            width if width is None else int(width),
        )

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        if enabled:
            command = "set python print-stack full"
        else:
            command = "set python print-stack message"

        gdb.execute(command, from_tty=True, to_string=True)
