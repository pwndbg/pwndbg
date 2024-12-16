"""
Heap Tracking

This module implements runtime tracking of the heap, allowing pwndbg to detect
heap related misbehavior coming from an inferior in real time, which lets us
catch UAF bugs, double frees (and more), and report them to the user.

# Approach
The approach used starting with using breakpoints to hook into the following
libc symbols: `malloc`, `free`, `calloc`, and `realloc`. Each hook has a
reference to a shared instance of the `Tracker` class, which is responsible for
handling the tracking of the chunks of memory from the heap.

The tracker keeps two sorted maps of chunks, for freed and in use chunks, keyed
by their base address. Newly allocated chunks are added to the map of in use
chunks right before an allocating call returns, and newly freed chunks are moved
from the map of in use chunks to the map of free ones right before a freeing
call returns. The tracker is also responsible for installing watchpoints for
free chunks when they're added to the free chunk map and deleting them when
their corresponding chunks are removed from the map.

Additionally, because going through the data structures inside of libc to
determine whether a chunk is free or not is, more often than not, a fairly slow
operation, this module will only do so when it determines its view of the chunks
has diverged from the one in libc in a way that would affect behavior. When such
a diffence is detected, this module will rebuild the chunk maps in the range it
determines to have been affected.

Currently, the way it does this is by deleting and querying from libc the new
status of all chunks that overlap the region of a new allocation when it detects
that allocation overlaps chunks it previously considered free.

This approach lets us avoid a lot of the following linked lists that comes with
trying to answer the allocation status of a chunk, by keeping at hand as much
known-good information as possible about them. Keep in mind that, although it is
much faster than going to libc every time we need to know the allocation status
of a chunk, this approach does have drawbacks when it comes to memory usage.

# Compatibility
Currently module assumes the inferior is using GLibc.

There are points along the code in this module where the assumptions it makes
are explicitly documented and checked to be valid for the current inferior, so
that it may be immediately clear to the user that something has gone wrong if
they happen to not be valid. However, be aware that there may be assumptions
that were not made explicit.

"""

from __future__ import annotations

from typing import Dict
from typing import List

import gdb
from sortedcontainers import SortedDict

import pwndbg.aglib.heap
import pwndbg.aglib.heap.ptmalloc
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.lib.cache
from pwndbg.color import message

LIBC_NAME = "libc.so.6"
MALLOC_NAME = "malloc"
CALLOC_NAME = "calloc"
REALLOC_NAME = "realloc"
FREE_NAME = "free"

last_issue: str | None = None

# Useful to track possbile collision errors.
PRINT_DEBUG = False


def is_enabled() -> bool:
    """
    Whether the heap tracker in enabled.
    """
    global malloc_enter
    global free_enter

    installed = [malloc_enter is not None, free_enter is not None]

    # Make sure we're not in an inconsistent state.
    assert all(installed) == any(installed)

    return any(installed)


def resolve_address(name: str) -> int | None:
    """
    Checks whether a given symbol is available and part of libc, and returns its
    address.
    """
    # If that fails, try to query for it by using the less precise pwndbg API.
    address = pwndbg.aglib.symbol.lookup_symbol_addr(name)
    if not address:
        # Nothing that we can do here.
        return None

    # TODO: dodanie do lookup_symbol, sprawdzanie do jakiego modulu jest przypisany
    # Try to see if this belongs to libc.
    #
    # This check is, frankly, horrifying, but it's one of the few ways we can
    # check what objfile the address we got is coming from*, and it's better to
    # err on the side of caution here and at least attempt to prevent the wrong
    # symbol from being used, than to return a possibly wrong symbol and have
    # the user wonder why on Earth the heap tracker would be hooking to ld.so.
    #
    # *: A better way would be to use gdb.objfile_from_address, but that's only
    # available in relatively recent versions of GDB.
    info = gdb.execute(f"info symbol {address:#x}", to_string=True, from_tty=False)
    info = info.split(" of ")[-1].split("/")[-1]
    if not info or LIBC_NAME not in info:
        print(
            message.warn(
                f'Found "{name}" that does not seem to belong to {LIBC_NAME}. Refusing to use.'
            )
        )
        return None

    return address


class FreeChunkWatchpoint(gdb.Breakpoint):
    def __init__(self, chunk: Chunk, tracker: Tracker) -> None:
        self.chunk = chunk
        self.tracker = tracker

        language = gdb.execute("show language", to_string=True)
        if "rust" in language:
            loc = f"*({chunk.address:#x} as *mut [u8;{chunk.size}])"
        else:
            loc = f"*(char[{chunk.size}]*){chunk.address:#x}"

        super().__init__(loc, type=gdb.BP_WATCHPOINT, internal=True)

    def stop(self):
        pwndbg.lib.cache.clear_cache("stop")
        if not in_program_code_stack():
            # Untracked.
            return False

        # malloc() and free() implementations will often modify the data in the
        # payload of a freed chunk, where the watchpoint is insalled. So, we
        # should not flag accesses done as a result of a call to either.
        if self.tracker.is_performing_memory_management():
            # We explicitly allow this operation.
            return False

        msg = f"Possible use-after-free in {self.chunk.size}-byte chunk at address {self.chunk.address:#x}"
        print(f"[!] {msg}")

        global stop_on_error
        if stop_on_error:
            global last_issue
            last_issue = message.error(msg)
        return stop_on_error


class AllocChunkWatchpoint(gdb.Breakpoint):
    def __init__(self, chunk: Chunk) -> None:
        self.chunk = chunk
        super().__init__(f"*(char[{chunk.size}]*){chunk.address:#x}", internal=True)

    def stop(self) -> bool:
        return False


class Chunk:
    def __init__(self, address: int, size: int, requested_size: int, flags: int) -> None:
        self.address = address
        self.size = size
        self.requested_size = requested_size
        self.flags = flags


# GDB doesn't like having its breakpoints deleted during stop handlers, so we
# defer deletion until the next stop event.
DEFERED_DELETE: List[gdb.Breakpoint] = []


@pwndbg.dbg.event_handler(pwndbg.dbg_mod.EventType.STOP)
def _delete_defered():
    for entry in DEFERED_DELETE:
        entry.delete()
    DEFERED_DELETE.clear()


class Tracker:
    def __init__(self) -> None:
        self.free_chunks: SortedDict[int, Chunk] = SortedDict()
        self.alloc_chunks: SortedDict[int, Chunk] = SortedDict()
        self.free_watchpoints: Dict[int, FreeChunkWatchpoint] = {}
        self.memory_management_calls: Dict[int, bool] = {}

    def is_performing_memory_management(self):
        thread = gdb.selected_thread().global_num
        if thread not in self.memory_management_calls:
            return False
        else:
            return self.memory_management_calls[thread]

    def enter_memory_management(self, name: str) -> None:
        thread = gdb.selected_thread().global_num

        # We don't support re-entry.
        if thread in self.memory_management_calls:
            assert not self.memory_management_calls[
                thread
            ], f"in {name}(): re-entrant calls are not supported"

        self.memory_management_calls[thread] = True

    def exit_memory_management(self) -> None:
        thread = gdb.selected_thread().global_num

        # Make sure we're not doing anything wrong.
        if thread in self.memory_management_calls:
            assert self.memory_management_calls[
                thread
            ], "exit_memory_management_calls assert failed"

        self.memory_management_calls[thread] = False

    def malloc(self, chunk: Chunk) -> None:
        # malloc()s may arbitrarily change the structure of freed blocks, to the
        # point our chunk maps may become invalid, so, we update them here if
        # anything looks wrong.
        lo_i = self.free_chunks.bisect_right(chunk.address)
        hi_i = self.free_chunks.bisect_right(chunk.address + chunk.size)
        if lo_i > 0:
            left_chunk = self.free_chunks.peekitem(index=lo_i - 1)[1]
            if left_chunk.address + left_chunk.size >= chunk.address:
                # Include the element to the left in the update.
                lo_i -= 1

        try:
            if lo_i != hi_i:
                # The newly registered chunk overlaps with chunks we had registered
                # previously, which means our libc shuffled some things around and
                # so we need to update our view of the chunks.
                lo_chunk = self.free_chunks.peekitem(index=lo_i)[1]
                hi_chunk = self.free_chunks.peekitem(index=hi_i - 1)[1]

                lo_addr = lo_chunk.address
                hi_addr = hi_chunk.address + hi_chunk.size

                lo_heap = pwndbg.aglib.heap.ptmalloc.Heap(lo_addr)
                hi_heap = pwndbg.aglib.heap.ptmalloc.Heap(hi_addr - 1)
                assert (
                    lo_heap.arena is not None and hi_heap.arena is not None
                ), "malloc assert failed"

                # TODO: Can this ever actually fail in real world use?
                #
                # It shouldn't be possible, the way glibc implements it[0], to have
                # a contiguous range at time t+1 that overlaps with two or more
                # contiguous ranges that at time t belonged to different heaps.
                #
                # glibc doesn't move or resize its heaps, which means the boundaries
                # between them stay fixed, and, since a chunk can only be created
                # from slicing a heap, the heap used to create the chunk at t+1 must
                # be the same as the one used to create the ranges at t that it
                # overlaps with.
                #
                # The question is, if we were to support other implementations, we
                # couldn't take this behavior for granted. Regardless, if we ever
                # do, it's better to fail here if/when this assumption is violated
                # than to let it become a bug.
                #
                # [0]: https://sourceware.org/glibc/wiki/MallocInternals
                assert (
                    lo_heap.start == hi_heap.start and lo_heap.end == hi_heap.end
                ), "malloc assert start failed"

                # Remove all of our old handlers.
                for i in reversed(range(lo_i, hi_i)):
                    addr, ch = self.free_chunks.popitem(index=i)

                    self.free_watchpoints[addr].enabled = False
                    DEFERED_DELETE.append(self.free_watchpoints[addr])
                    del self.free_watchpoints[addr]

                # Add new handlers in their place. We scan over all of the chunks in
                # the heap in the range of affected chunks, and add the ones that
                # are free.
                allocator = pwndbg.aglib.heap.current
                assert isinstance(
                    allocator, pwndbg.aglib.heap.ptmalloc.GlibcMemoryAllocator
                ), "malloc allocator assert failed"
                bins_list = [
                    allocator.fastbins(lo_heap.arena.address),
                    allocator.smallbins(lo_heap.arena.address),
                    allocator.largebins(lo_heap.arena.address),
                    allocator.unsortedbin(lo_heap.arena.address),
                ]
                if allocator.has_tcache():
                    bins_list.append(allocator.tcachebins(None))
                bins_list = [x for x in bins_list if x is not None]

                for ch in lo_heap:
                    # Check for range overlap.
                    ch_lo_addr = ch.address
                    ch_hi_addr = ch.address + ch.size
                    ch.address

                for ch in lo_heap:
                    # Check for range overlap.
                    ch_lo_addr = ch.address
                    ch_hi_addr = ch.address + ch.size

                    lo_in_range = ch_lo_addr < hi_addr
                    hi_in_range = ch_hi_addr > lo_addr

                    if not lo_in_range or not hi_in_range:
                        # No range overlap.
                        continue

                    # Check if the chunk is free.
                    for b in bins_list:
                        if b.contains_chunk(ch.real_size, ch.address):
                            # The chunk is free. Add it to the free list and install
                            # a new watch point for it.
                            nch = Chunk(ch.address, ch.size, ch.real_size, 0)
                            wp = FreeChunkWatchpoint(nch, self)

                            self.free_chunks[ch.address] = nch
                            self.free_watchpoints[ch.address] = wp

                            # Move on to the next chunk.
                            break
        except IndexError:
            import traceback

            traceback.print_exc()

        self.alloc_chunks[chunk.address] = chunk

    def free(self, address: int) -> bool:
        if address not in self.alloc_chunks:
            return False
        chunk = self.alloc_chunks[address]
        del self.alloc_chunks[address]

        wp = FreeChunkWatchpoint(chunk, self)

        self.free_chunks[chunk.address] = chunk
        self.free_watchpoints[chunk.address] = wp

        return True


class MallocEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, address, tracker) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.tracker = tracker

    def stop(self) -> bool:
        pwndbg.lib.cache.clear_cache("stop")
        requested_size = pwndbg.arguments.argument(0)
        if self.tracker.is_performing_memory_management():
            # This call was made from inside another memory management call.
            # Ignore it.
            return False

        self.tracker.enter_memory_management(MALLOC_NAME)
        AllocExitBreakpoint(self.tracker, requested_size, f"malloc({requested_size})")
        return False


class CallocEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, address, tracker) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.tracker = tracker

    def stop(self) -> bool:
        pwndbg.lib.cache.clear_cache("stop")

        num_elements = pwndbg.arguments.argument(0)
        element_size = pwndbg.arguments.argument(1)
        requested_size = element_size * num_elements
        if self.tracker.is_performing_memory_management():
            # This call was made from inside another memory management call.
            # Ignore it.
            return False

        self.tracker.enter_memory_management(CALLOC_NAME)
        AllocExitBreakpoint(self.tracker, requested_size, f"calloc({num_elements}, {element_size})")
        return False


def get_chunk(address, requested_size):
    """
    Reads a chunk from a given address.
    """
    ty = pwndbg.aglib.typeinfo.ppvoid
    size = int(pwndbg.aglib.memory.get_typed_pointer_value(ty, address - ty.sizeof))

    # GLibc bakes the chunk flags in the lowest 3 bits of the size value,
    # so, we separate them here.
    FLAGS_BITMASK = 7

    flags = size & FLAGS_BITMASK
    size ^= flags

    return Chunk(address, size, requested_size, flags)


class AllocExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, tracker, requested_size, name) -> None:
        super().__init__(internal=True)
        self.requested_size = requested_size
        self.tracker = tracker
        self.name = name

    def stop(self) -> bool:
        pwndbg.lib.cache.clear_cache("stop")
        if not in_program_code_stack():
            # Untracked.
            self.tracker.exit_memory_management()
            return False

        ret_ptr = int(self.return_value)
        if ret_ptr == 0:
            # No change.
            self.tracker.exit_memory_management()
            return False

        chunk = get_chunk(ret_ptr, self.requested_size)
        self.tracker.malloc(chunk)
        print(f"[*] {self.name} -> {ret_ptr:#x}, {chunk.size} bytes real size")

        self.tracker.exit_memory_management()
        return False

    def out_of_scope(self) -> None:
        print(
            message.warn(
                f"warning: could not follow allocation request of {self.requested_size} bytes"
            )
        )
        self.tracker.exit_memory_management()


class ReallocEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, address, tracker) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.tracker = tracker

    def stop(self) -> bool:
        pwndbg.lib.cache.clear_cache("stop")

        freed_pointer = pwndbg.arguments.argument(0)
        requested_size = pwndbg.arguments.argument(1)
        if self.tracker.is_performing_memory_management():
            # This call was made from inside another memory management call.
            # Ignore it.
            return False

        self.tracker.enter_memory_management(REALLOC_NAME)

        if requested_size == 0:
            # There's no right way to handle realloc(..., 0). C23 says it's
            # undefined behavior, and prior versions say it's implementation-
            # defined. Either way, print a warning and do nothing.
            print(
                message.warn(
                    f"[-] realloc({self.freed_pointer:#x}, {requested_size}) ignored, as realloc(0, ...) is implementation defined"
                )
            )
            return False

        if freed_pointer == 0:
            # Treat this realloc same as malloc
            AllocExitBreakpoint(self.tracker, requested_size, f"realloc(0x0, {requested_size})")
        else:
            ReallocExitBreakpoint(self.tracker, freed_pointer, requested_size)
        return False


class ReallocExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, tracker, freed_ptr, requested_size) -> None:
        super().__init__(internal=True)
        self.freed_ptr = freed_ptr
        self.requested_size = requested_size
        self.tracker = tracker

    def stop(self):
        pwndbg.lib.cache.clear_cache("stop")
        if not in_program_code_stack():
            # Untracked.
            self.tracker.exit_memory_management()
            return False

        # Figure out what the reallocated pointer is.
        ret_ptr = int(self.return_value)
        if ret_ptr == 0:
            # No change.
            malloc = None
        chunk = get_chunk(ret_ptr, self.requested_size)
        malloc = lambda: self.tracker.malloc(chunk)

        if not self.tracker.free(self.freed_ptr):
            # This is a chunk we'd never seen before.
            malloc()
            self.tracker.exit_memory_management()

            msg = f"realloc() to {self.requested_size} bytes with previously unknown pointer {self.freed_ptr:#x}"
            print(f"[!] {msg}")

            global stop_on_error
            if stop_on_error:
                global last_issue
                last_issue = message.error(msg)
            return stop_on_error

        malloc()
        self.tracker.exit_memory_management()

        print(
            f"[*] realloc({self.freed_ptr:#x}, {self.requested_size}) -> {ret_ptr:#x}, {chunk.size} bytes real size"
        )
        return False

    def out_of_scope(self) -> None:
        print(message.warn(f"warning: could not follow free request for chunk {self.freed_ptr:#x}"))
        self.tracker.exit_memory_management()


class FreeEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, address, tracker) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.tracker = tracker

    def stop(self) -> bool:
        pwndbg.lib.cache.clear_cache("stop")
        ptr = pwndbg.arguments.argument(0)
        if self.tracker.is_performing_memory_management():
            # This call was made from inside another memory management call.
            # Ignore it.
            return False
        if ptr == 0:
            # free(0) is a no-op.
            print("[*] free(0x0)")
            return False

        self.tracker.enter_memory_management(FREE_NAME)
        FreeExitBreakpoint(self.tracker, ptr)
        return False


class FreeExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, tracker, ptr) -> None:
        super().__init__(internal=True)
        self.ptr = ptr
        self.tracker = tracker

    def stop(self):
        pwndbg.lib.cache.clear_cache("stop")
        if not in_program_code_stack():
            # Untracked.
            self.tracker.exit_memory_management()
            return False

        if not self.tracker.free(self.ptr):
            # This is a chunk we'd never seen before.
            self.tracker.exit_memory_management()

            msg = f"free() with previously unknown pointer {self.ptr:#x}"
            print(f"[!] {msg}")
            global stop_on_error
            if stop_on_error:
                global last_issue
                last_issue = message.error(msg)
            return stop_on_error

        self.tracker.exit_memory_management()

        print(f"[*] free({self.ptr:#x})")
        return False

    def out_of_scope(self) -> None:
        print(message.warn(f"warning: could not follow free request for chunk {self.ptr:#x}"))
        self.tracker.exit_memory_management()


def in_program_code_stack() -> bool:
    exe = pwndbg.aglib.proc.exe
    binary_exec_page_ranges = tuple(
        (p.start, p.end) for p in pwndbg.aglib.vmmap.get() if p.objfile == exe and p.execute
    )

    frame = gdb.newest_frame()
    while frame is not None:
        pc = frame.pc()
        for start, end in binary_exec_page_ranges:
            if start <= pc < end:
                return True
        frame = frame.older()
    return False


# These variables track the currently installed heap tracker.
malloc_enter = None
calloc_enter = None
realloc_enter = None
free_enter = None

# Whether the inferior should be stopped when an error is detected.
stop_on_error = True


def install(disable_hardware_watchpoints=True) -> None:
    global malloc_enter
    global calloc_enter
    global realloc_enter
    global free_enter

    if is_enabled():
        print("Nothing to do.")
        return

    # Make sure the required functions are available.
    required_symbols = [MALLOC_NAME, FREE_NAME]
    available = [resolve_address(name) for name in required_symbols]

    if not all(available):
        print(message.error("The following required symbols are not available:"))
        for name in (x[0] for x in zip(required_symbols, available) if not x[1]):
            print(message.error(f"    - {name}"))
        print(message.error(f"Make sure {LIBC_NAME} has already been loaded."))

        return

    # Warn our users that this is still an experimental feature and that due to
    # limitations in how GDB handles breakpoint creation and deletion during
    # processing of stop events for other breakpoints, there's not a lot we can
    # do about it currently.
    #
    # See https://sourceware.org/pipermail/gdb/2024-January/051062.html
    print(
        message.warn(
            "This feature is experimental and is known to report false positives, take the"
        )
    )
    print(message.warn("diagnostics it procudes with a grain of salt. Use at your own risk."))
    print()

    # Disable hardware watchpoints.
    #
    # We don't really know how to make sure that the hardware watchpoints
    # present in the system have enough capabilities for them to be useful to
    # us in this module, seeing as what they can do varies considerably between
    # systems and failures are fairly quiet and, thus, hard to detect[1].
    # Because of this, we opt to disable them by default for the sake of
    # consistency and so that we don't have to chase silent failures.
    #
    # [1]: https://sourceware.org/gdb/onlinedocs/gdb/Set-Watchpoints.html
    if disable_hardware_watchpoints:
        gdb.execute("set can-use-hw-watchpoints 0")
        print("Hardware watchpoints have been disabled. Please do not turn them back on until")
        print("heap tracking is disabled, as it may lead to unexpected silent errors.")
        print()
        print("They may be re-enabled with `set can-use-hw-watchpoints 1`")
        print()
    else:
        print(
            message.warn("Hardware watchpoints have not been disabled, silent errors may happen.")
        )
        print()

    # Install the heap tracker.
    tracker = Tracker()

    malloc_enter = MallocEnterBreakpoint(available[0], tracker)
    free_enter = FreeEnterBreakpoint(available[1], tracker)

    calloc_address = resolve_address(CALLOC_NAME)
    if calloc_address:
        calloc_enter = CallocEnterBreakpoint(calloc_address, tracker)

    realloc_address = resolve_address(REALLOC_NAME)
    if realloc_address:
        realloc_enter = ReallocEnterBreakpoint(realloc_address, tracker)

    print("Heap tracker installed.")


def uninstall() -> None:
    global malloc_enter
    global calloc_enter
    global realloc_enter
    global free_enter

    if is_enabled():
        malloc_enter.delete()
        free_enter.delete()

        malloc_enter = None
        free_enter = None

        if calloc_enter is not None:
            calloc_enter.delete()
            calloc_enter = None
        if realloc_enter is not None:
            realloc_enter.delete()
            realloc_enter = None

        print("Heap tracker removed.")
    else:
        print("Nothing to do.")
