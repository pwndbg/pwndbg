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

import gdb
from sortedcontainers import SortedDict

import pwndbg.gdblib

MALLOC_NAME = "malloc"
FREE_NAME = "free"


class FreeChunkWatchpoint(gdb.Breakpoint):
    def __init__(self, chunk, tracker):
        self.chunk = chunk
        self.tracker = tracker
        super().__init__(
            f"*(char[{chunk.size}]*){chunk.address:#x}", type=gdb.BP_WATCHPOINT, internal=True
        )

    def stop(self):
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        if not in_program_code_stack():
            # Untracked.
            return False

        # malloc() and free() implementations will often modify the data in the
        # payload of a freed chunk, where the watchpoint is insalled. So, we
        # should not flag accesses done as a result of a call to either.
        if self.tracker.is_performing_memory_management():
            # We explicitly allow this operation.
            return False

        return True


class AllocChunkWatchpoint(gdb.Breakpoint):
    def __init__(self, chunk):
        pwndbg.gdblib.regs.__getattr__.cache.clear()

        self.chunk = chunk
        super().__init__(f"*(char[{chunk.size}]*){chunk.address:#x}", internal=True)

    def stop(self):
        return False


class Chunk:
    def __init__(self, address, size, requested_size, flags):
        self.address = address
        self.size = size
        self.requested_size = requested_size
        self.flags = flags


class Tracker:
    def __init__(self):
        self.free_chunks = SortedDict()
        self.alloc_chunks = SortedDict()
        self.free_wps = dict()
        self.memory_management_calls = dict()

    def is_performing_memory_management(self):
        thread = gdb.selected_thread().global_num

        if thread not in self.memory_management_calls:
            return False
        else:
            return self.memory_management_calls[thread]

    def enter_memory_management(self):
        thread = gdb.selected_thread().global_num
        self.memory_management_calls[thread] = True

    def exit_memory_management(self):
        thread = gdb.selected_thread().global_num
        self.memory_management_calls[thread] = False

    def malloc(self, chunk):
        print(f"Allocated {chunk.size:#x} byte chunk at {chunk.address:#x}")

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

        print("    map:")
        for ch in self.free_chunks:
            print(f"        {self.free_chunks[ch].address:#x} ({self.free_chunks[ch].size} bytes)")
        print(f"    lo_i: {lo_i}")
        print(f"    hi_i: {hi_i}")

        if lo_i != hi_i:
            # The newly registered chunk overlaps with chunks we had registered
            # previously, which means our libc shuffled some things around and
            # so we need to update our view of the chunks.
            lo_chunk = self.free_chunks.peekitem(index=lo_i)[1]
            hi_chunk = self.free_chunks.peekitem(index=hi_i - 1)[1]

            lo_addr = lo_chunk.address
            hi_addr = hi_chunk.address + hi_chunk.size

            print(f"    lo_addr: {lo_addr:#x}")
            print(f"    hi_addr: {hi_addr:#x}")

            lo_heap = pwndbg.heap.ptmalloc.Heap(lo_addr)
            hi_heap = pwndbg.heap.ptmalloc.Heap(hi_addr - 1)

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
            assert lo_heap.start == hi_heap.start and lo_heap.end == hi_heap.end

            # Remove all of our old handlers.
            for i in range(lo_i, hi_i):
                addr, ch = self.free_chunks.popitem(index=i)

                self.free_wps[addr].delete()
                del self.free_wps[addr]

            # Add new handlers in their place. We scan over all of the chunks in
            # the heap in the range of affected chunks, and add the ones that
            # are free.
            allocator = pwndbg.heap.current
            bins_list = [
                allocator.fastbins(lo_heap.arena.address),
                allocator.smallbins(lo_heap.arena.address),
                allocator.largebins(lo_heap.arena.address),
                allocator.unsortedbin(lo_heap.arena.address),
            ]
            if allocator.has_tcache():
                bins_list.append(allocator.tcachebins(None))
            bins_list = [x for x in bins_list if x is not None]

            print(f"Chunks in heap {lo_heap.start:#x}-{lo_heap.end:#x}:")
            for ch in lo_heap:
                # Check for range overlap.
                ch_lo_addr = ch.address
                ch_hi_addr = ch.address + ch.size

                print(f"        {ch.address:#x} ({ch.real_size} bytes)", end="")

                lo_in_range = ch_lo_addr < hi_addr
                hi_in_range = ch_hi_addr > lo_addr

                if not lo_in_range or not hi_in_range:
                    # No range overlap.
                    print(" (out of range)")
                    continue

                # Check if the chunk is free.
                found = False
                for b in bins_list:
                    if b.contains_chunk(ch.real_size, ch.address):
                        # The chunk is free. Add it to the free list and install
                        # a new watch point for it.
                        nch = Chunk(ch.address, ch.size, ch.real_size, 0)
                        wp = FreeChunkWatchpoint(nch, self)

                        print(" (free)")

                        self.free_chunks[ch.address] = nch
                        self.free_wps[ch.address] = wp

                        # Move on to the next chunk.
                        found = True
                        break
                if not found:
                    print(" (in use)")

        self.alloc_chunks[chunk.address] = chunk

    def free(self, address) -> bool:
        if address not in self.alloc_chunks:
            return False
        chunk = self.alloc_chunks[address]
        wp = FreeChunkWatchpoint(chunk, self)

        self.free_chunks[chunk.address] = chunk
        self.free_wps[chunk.address] = wp

        return True


class MallocEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, tracker):
        super().__init__(MALLOC_NAME, internal=True)
        self.tracker = tracker

    def stop(self):
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        requested_size = pwndbg.arguments.argument(0)

        self.tracker.enter_memory_management()
        MallocExitBreakpoint(self.tracker, requested_size)
        return False


class MallocExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, tracker, requested_size):
        super().__init__(internal=True)
        self.requested_size = requested_size
        self.tracker = tracker

    def stop(self):
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        if not in_program_code_stack():
            # Untracked.
            self.tracker.exit_memory_management()
            return False

        ret_ptr = int(self.return_value)
        if ret_ptr == 0:
            # No change.
            self.tracker.exit_memory_management()
            return False

        ty = pwndbg.gdblib.typeinfo.ppvoid
        size = int(pwndbg.gdblib.memory.poi(ty, ret_ptr - ty.sizeof))

        flags = size & 7
        size ^= flags

        chunk = Chunk(ret_ptr, size, self.requested_size, flags)
        self.tracker.malloc(chunk)
        print(
            f"Allocated {size} byte chunk ({self.requested_size} bytes requested) starting at {ret_ptr:#x}"
        )

        self.tracker.exit_memory_management()
        return False


class FreeEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, tracker):
        super().__init__(FREE_NAME, internal=True)
        self.tracker = tracker

    def stop(self):
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        ptr = pwndbg.arguments.argument(0)

        self.tracker.enter_memory_management()
        FreeExitBreakpoint(self.tracker, ptr)
        return False


class FreeExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, tracker, ptr):
        super().__init__(internal=True)
        self.ptr = ptr
        self.tracker = tracker

    def stop(self):
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        if not in_program_code_stack():
            # Untracked.
            self.tracker.exit_memory_management()
            return False

        print(f"Trying to free chunk starting at {self.ptr:#x}")
        if not self.tracker.free(self.ptr):
            # This is a chunk we'd never seen before.
            self.tracker.exit_memory_management()
            return True

        self.tracker.exit_memory_management()
        return False


def in_program_code_stack():
    exe = pwndbg.gdblib.proc.exe
    binary_exec_page_ranges = tuple(
        (p.start, p.end) for p in pwndbg.gdblib.vmmap.get() if p.objfile == exe and p.execute
    )

    frame = gdb.newest_frame()
    while frame is not None:
        pc = frame.pc()
        for start, end in binary_exec_page_ranges:
            if start <= pc < end:
                return True
        frame = frame.older()
    return False


def install():
    tracker = Tracker()
    MallocEnterBreakpoint(tracker)
    FreeEnterBreakpoint(tracker)
