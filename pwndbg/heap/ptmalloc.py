from collections import OrderedDict

import gdb

import pwndbg.color.memory as M
import pwndbg.disasm
import pwndbg.events
import pwndbg.glibc
import pwndbg.search
import pwndbg.symbol
import pwndbg.typeinfo
import pwndbg.vmmap
from pwndbg.color import message
from pwndbg.constants import ptmalloc
from pwndbg.heap import heap_chain_limit

# See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l30
# and https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l869
# 1 Mb (x86) or 64 Mb (x64)
HEAP_MAX_SIZE = 1024 * 1024 if pwndbg.arch.ptrsize == 4 else 2 * 4 * 1024 * 1024 * 8


def heap_for_ptr(ptr):
    """Round a pointer to a chunk down to find its corresponding heap_info
    struct, the pointer must point inside a heap which does not belong to
    the main arena.
    """
    return (ptr & ~(HEAP_MAX_SIZE-1))


class Arena:
    def __init__(self, addr, heaps):
        self.addr  = addr
        self.heaps = heaps

    def __str__(self):
        res = []
        prefix = '[%%%ds]    ' % (pwndbg.arch.ptrsize * 2)
        prefix_len = len(prefix % (''))
        arena_name = hex(self.addr) if self.addr != pwndbg.heap.current.main_arena.address else 'main'
        res.append(message.hint(prefix % (arena_name)) + str(self.heaps[0]))
        for h in self.heaps[1:]:
            res.append(' ' * prefix_len + str(h))

        return '\n'.join(res)


class HeapInfo:
    def __init__(self, addr, first_chunk):
        self.addr        = addr
        self.first_chunk = first_chunk

    def __str__(self):
        fmt = '[%%%ds]' % (pwndbg.arch.ptrsize * 2)
        return message.hint(fmt % (hex(self.first_chunk))) + M.heap(str(pwndbg.vmmap.find(self.addr)))


class Heap(pwndbg.heap.heap.BaseHeap):
    def __init__(self):
        # Global ptmalloc objects
        self._global_max_fast_addr = None
        self._global_max_fast      = None
        self._main_arena_addr      = None
        self._main_arena           = None
        self._mp_addr              = None
        self._mp                   = None
        # List of arenas/heaps
        self._arenas               = None
        # ptmalloc cache for current thread
        self._thread_cache         = None

    @property
    def main_arena(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_stop
    def arenas(self):
        arena           = self.main_arena
        arenas          = []
        arena_cnt       = 0
        main_arena_addr = int(arena.address)
        sbrk_page       = self.get_heap_boundaries().vaddr

        # Create the main_arena with a fake HeapInfo
        main_arena      = Arena(main_arena_addr, [HeapInfo(sbrk_page, sbrk_page)])
        arenas.append(main_arena)

        # Iterate over all the non-main arenas
        addr = int(arena['next'])
        while addr != main_arena_addr:
            heaps = []
            arena = self.get_arena(addr)
            arena_cnt += 1

            # Get the first and last element on the heap linked list of the arena
            last_heap_addr  = heap_for_ptr(int(arena['top']))
            first_heap_addr = heap_for_ptr(addr)

            heap = self.get_heap(last_heap_addr)
            if not heap:
                print(message.error('Could not find the heap for arena %s' % hex(addr)))
                return

            # Iterate over the heaps of the arena
            haddr = last_heap_addr
            while haddr != 0:
                if haddr == first_heap_addr:
                    # The first heap has a heap_info and a malloc_state before the actual chunks
                    chunks_offset = self.heap_info.sizeof + self.malloc_state.sizeof
                else:
                    # The others just
                    chunks_offset = self.heap_info.sizeof
                heaps.append(HeapInfo(haddr, haddr + chunks_offset))

                # Name the heap mapping, so that it can be colored properly. Note that due to the way malloc is
                # optimized, a vm mapping may contain two heaps, so the numbering will not be exact.
                page = self.get_region(haddr)
                page.objfile = '[heap %d:%d]' % (arena_cnt, len(heaps))
                heap = self.get_heap(haddr)
                haddr = int(heap['prev'])

            # Add to the list of arenas and move on to the next one
            arenas.append(Arena(addr, tuple(reversed(heaps))))
            addr = int(arena['next'])

        arenas = tuple(arenas)
        self._arenas = arenas
        return arenas

    def has_tcache(self):
        raise NotImplementedError()

    @property
    def thread_cache(self):
        raise NotImplementedError()
    
    @property
    def mp(self):
        raise NotImplementedError()
    
    @property
    def global_max_fast(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_objfile
    def heap_info(self):
        raise NotImplementedError()
    
    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_chunk(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_state(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_entry(self):
        raise NotImplementedError()
    
    @property
    @pwndbg.memoize.reset_on_objfile
    def mallinfo(self):
        raise NotImplementedError()
    
    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_par(self):
        raise NotImplementedError()

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_alignment(self):
        """Corresponds to MALLOC_ALIGNMENT in glibc malloc.c"""
        return pwndbg.arch.ptrsize * 2

    @property
    @pwndbg.memoize.reset_on_objfile
    def size_sz(self):
        """Corresponds to SIZE_SZ in glibc malloc.c"""
        return pwndbg.arch.ptrsize

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_align_mask(self):
        """Corresponds to MALLOC_ALIGN_MASK in glibc malloc.c"""
        return self.malloc_alignment - 1

    @property
    @pwndbg.memoize.reset_on_objfile
    def minsize(self):
        """Corresponds to MINSIZE in glibc malloc.c"""
        return self.min_chunk_size

    @property
    @pwndbg.memoize.reset_on_objfile
    def min_chunk_size(self):
        """Corresponds to MIN_CHUNK_SIZE in glibc malloc.c"""
        return pwndbg.arch.ptrsize * 4

    @property
    @pwndbg.memoize.reset_on_objfile
    def multithreaded(self):
        """Is malloc operating within a multithreaded environment."""
        addr = pwndbg.symbol.address('__libc_multiple_threads')
        if addr:
            return pwndbg.memory.s32(addr) > 0
        return len(gdb.execute('info threads', to_string=True).split('\n')) > 3

    def _request2size(self, req):
        """Corresponds to request2size in glibc malloc.c"""
        if req + self.size_sz + self.malloc_align_mask < self.minsize:
            return self.minsize
        return (req + self.size_sz + self.malloc_align_mask) & ~self.malloc_align_mask

    def _spaces_table(self):
        spaces_table =  [ pwndbg.arch.ptrsize * 2 ]      * 64 \
                      + [ pow(2, 6) ]                    * 32 \
                      + [ pow(2, 9) ]                    * 16 \
                      + [ pow(2, 12) ]                   * 8  \
                      + [ pow(2, 15) ]                   * 4  \
                      + [ pow(2, 18) ]                   * 2  \
                      + [ pow(2, 21) ]                   * 1

        # There is no index 0
        spaces_table = [ None ] + spaces_table

        # Fix up the slop in bin spacing (part of libc - they made
        # the trade off of some slop for speed)
        # https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1356
        if pwndbg.arch.ptrsize == 8:
            spaces_table[97] = 64
            spaces_table[98] = 448

        spaces_table[113] = 1536
        spaces_table[121] = 24576
        spaces_table[125] = 98304

        return spaces_table

    def chunk_flags(self, size):
        return ( size & ptmalloc.PREV_INUSE ,
                 size & ptmalloc.IS_MMAPPED,
                 size & ptmalloc.NON_MAIN_ARENA )

    def chunk_key_offset(self, key):
        """Find the index of a field in the malloc_chunk struct.

        64bit example:
            prev_size == 0
            size      == 8
            fd        == 16
            bk        == 24
            ...
        """
        renames = {
            "mchunk_size": "size",
            "mchunk_prev_size": "prev_size",
        }
        val = self.malloc_chunk
        chunk_keys = [renames[key] if key in renames else key for key in val.keys()]
        try:
            return chunk_keys.index(key) * pwndbg.arch.ptrsize
        except:
            return None

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_next_offset(self):
        return  self.tcache_entry.keys().index('next') * pwndbg.arch.ptrsize

    def get_heap(self, addr):
        raise NotImplementedError()

    def get_arena(self, arena_addr=None):
        raise NotImplementedError()

    def get_arena_for_chunk(self, addr):
        chunk = pwndbg.commands.heap.read_chunk(addr)
        _,_,nm = self.chunk_flags(chunk['size'])
        if nm:
            r=self.get_arena(arena_addr=self.get_heap(addr)['ar_ptr'])
        else:
            r=self.main_arena
        return r

    def get_tcache(self, tcache_addr=None):
        raise NotImplementedError()
    
    def get_heap_boundaries(self, addr=None):
        raise NotImplementedError()

    def get_region(self, addr):
        """Find the memory map containing 'addr'."""
        return pwndbg.vmmap.find(addr)

    def fastbin_index(self, size):
        if pwndbg.arch.ptrsize == 8:
            return (size >> 4) - 2
        else:
            return (size >> 3) - 2

    def fastbins(self, arena_addr=None):
        """Returns: chain or None"""
        arena = self.get_arena(arena_addr)

        if arena is None:
            return

        fastbinsY    = arena['fastbinsY']
        fd_offset    = self.chunk_key_offset('fd')
        num_fastbins = 7
        size         = pwndbg.arch.ptrsize * 2
        safe_lnk = pwndbg.glibc.check_safe_linking()

        result = OrderedDict()
        for i in range(num_fastbins):
            size += pwndbg.arch.ptrsize * 2
            chain = pwndbg.chain.get(int(fastbinsY[i]), offset=fd_offset, limit=heap_chain_limit, safe_linking=safe_lnk)

            result[size] = chain

        result['type'] = 'fastbins'
        return result

    def tcachebins(self, tcache_addr=None):
        """Returns: tuple(chain, count) or None"""
        tcache = self.get_tcache(tcache_addr)

        if tcache is None:
            return

        counts = tcache['counts']
        entries = tcache['entries']

        num_tcachebins = entries.type.sizeof // entries.type.target().sizeof
        safe_lnk = pwndbg.glibc.check_safe_linking()

        def tidx2usize(idx):
            """Tcache bin index to chunk size, following tidx2usize macro in glibc malloc.c"""
            return idx * self.malloc_alignment + self.minsize - self.size_sz

        result = OrderedDict()
        for i in range(num_tcachebins):
            size = self._request2size(tidx2usize(i))
            count = int(counts[i])
            chain = pwndbg.chain.get(int(entries[i]), offset=self.tcache_next_offset, limit=heap_chain_limit, safe_linking=safe_lnk)

            result[size] = (chain, count)

        result['type'] = 'tcachebins'
        return result

    def bin_at(self, index, arena_addr=None):
        """
        Modeled after glibc's bin_at function - so starts indexing from 1
        https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1394

        bin_at(1) returns the unsorted bin

        Bin 1          - Unsorted BiN
        Bin 2 to 63    - Smallbins
        Bin 64 to 126  - Largebins

        Returns: tuple(chain_from_bin_fd, chain_from_bin_bk, is_chain_corrupted) or None
        """
        index = index - 1
        arena = self.get_arena(arena_addr)

        if arena is None:
            return

        normal_bins = arena['bins']
        num_bins    = normal_bins.type.sizeof // normal_bins.type.target().sizeof

        bins_base    = int(normal_bins.address) - (pwndbg.arch.ptrsize* 2)
        current_base = bins_base + (index * pwndbg.arch.ptrsize * 2)

        front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
        fd_offset   = self.chunk_key_offset('fd')
        bk_offset   = self.chunk_key_offset('bk')

        is_chain_corrupted = False

        get_chain = lambda bin, offset: pwndbg.chain.get(int(bin), offset=offset, hard_stop=current_base, limit=heap_chain_limit, include_start=True)
        chain_fd = get_chain(front, fd_offset)
        chain_bk = get_chain(back, bk_offset)

        # check if bin[index] points to itself (is empty)
        if len(chain_fd) == len(chain_bk) == 2 and chain_fd[0] == chain_bk[0]:
            chain_fd = [0]
            chain_bk = [0]

        # check if corrupted
        elif chain_fd[:-1] != chain_bk[:-2][::-1] + [chain_bk[-2]]:
            is_chain_corrupted = True

        return (chain_fd, chain_bk, is_chain_corrupted)

    def unsortedbin(self, arena_addr=None):
        chain  = self.bin_at(1, arena_addr=arena_addr)
        result = OrderedDict()

        if chain is None:
            return

        result['all'] = chain

        result['type'] = 'unsortedbin'
        return result

    def smallbins(self, arena_addr=None):
        size         = self.min_chunk_size - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(2, 64):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        result['type'] = 'smallbins'
        return result

    def largebins(self, arena_addr=None):
        size         = (ptmalloc.NSMALLBINS * self.malloc_alignment) - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(64, 127):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        result['type'] = 'largebins'
        return result

    def largebin_index_32(self, sz):
        """Modeled on the GLIBC malloc largebin_index_32 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1414
        """
        return 56 + (sz >> 6) if (sz >> 6) <= 38 else\
        91 + (sz >> 9) if (sz >> 9) <= 20 else\
        110 + (sz >> 12) if (sz >> 12) <= 10 else\
        119 + (sz >> 15) if (sz >> 15) <= 4 else\
        124 + (sz >> 18) if (sz >> 18) <= 2 else\
        126

    def largebin_index_64(self, sz):
        """Modeled on the GLIBC malloc largebin_index_64 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1433
        """
        return 48 + (sz >> 6) if (sz >> 6) <= 48 else\
        91 + (sz >> 9) if (sz >> 9) <= 20 else\
        110 + (sz >> 12) if (sz >> 12) <= 10 else\
        119 + (sz >> 15) if (sz >> 15) <= 4 else\
        124 + (sz >> 18) if (sz >> 18) <= 2 else\
        126

    def largebin_index(self, sz):
        """Pick the appropriate largebin_index_ function for this architecture."""
        return self.largebin_index_64(sz) if pwndbg.arch.ptrsize == 8 else self.largebin_index_32(sz)

    def is_initialized(self):
        raise NotImplementedError()

    def libc_has_debug_syms(self):
        return pwndbg.symbol.address('global_max_fast') is not None

class DebugSymsHeap(Heap):
    @property
    def main_arena(self):
        self._main_arena_addr = pwndbg.symbol.address('main_arena')
        if self._main_arena_addr is not None:
            self._main_arena = pwndbg.memory.poi(self.malloc_state, self._main_arena_addr)

        return self._main_arena

    def has_tcache(self):
        return (self.mp and 'tcache_bins' in self.mp.type.keys() and self.mp['tcache_bins'])

    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. If it doesn't have one, use the main
        thread's tcache.
        """
        if self.has_tcache():
            tcache = self.mp['sbrk_base'] + 0x10
            if self.multithreaded:
                tcache_addr = pwndbg.memory.pvoid(pwndbg.symbol.address('tcache'))
                if tcache_addr != 0:
                    tcache = tcache_addr

            try:
                self._thread_cache = pwndbg.memory.poi(self.tcache_perthread_struct, tcache)
                _ = self._thread_cache['entries'].fetch_lazy()
            except Exception as e:
                print(message.error('Error fetching tcache. GDB cannot access '
                                    'thread-local variables unless you compile with -lpthread.'))
                return None

            return self._thread_cache

        else:
            print(message.warn('This version of GLIBC was not compiled with tcache support.'))
            return None

    @property
    def mp(self):
        self._mp_addr = pwndbg.symbol.address('mp_')
        if self._mp_addr is not None:
            self._mp = pwndbg.memory.poi(self.malloc_par, self._mp_addr)

        return self._mp

    @property
    def global_max_fast(self):
        self._global_max_fast_addr = pwndbg.symbol.address('global_max_fast')
        if self._global_max_fast_addr is not None:
            self._global_max_fast = pwndbg.memory.u(self._global_max_fast_addr)
        
        return self._global_max_fast

    @property
    @pwndbg.memoize.reset_on_objfile
    def heap_info(self):
        return pwndbg.typeinfo.load('heap_info')

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_chunk(self):
        return pwndbg.typeinfo.load('struct malloc_chunk')

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_state(self):
        return pwndbg.typeinfo.load('struct malloc_state')

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        return pwndbg.typeinfo.load('struct tcache_perthread_struct')

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_entry(self):
        return pwndbg.typeinfo.load('struct tcache_entry')

    @property
    @pwndbg.memoize.reset_on_objfile
    def mallinfo(self):
        return pwndbg.typeinfo.load('struct mallinfo')

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_par(self):
        return pwndbg.typeinfo.load('struct malloc_par')


    def get_heap(self, addr):
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        return pwndbg.memory.poi(self.heap_info, heap_for_ptr(addr))

    def get_arena(self, arena_addr=None):
        """Read a malloc_state struct from the specified address, default to
        reading the current thread's arena. Return the main arena if the
        current thread is not attached to an arena.
        """
        if arena_addr is None:
            if self.multithreaded:
                arena_addr = pwndbg.memory.u(pwndbg.symbol.address('thread_arena'))
                if arena_addr > 0:
                    return pwndbg.memory.poi(self.malloc_state, arena_addr)

            return self.main_arena

        try:
            next(i for i in pwndbg.vmmap.get() if arena_addr in i)
            return pwndbg.memory.poi(self.malloc_state, arena_addr)
        except (gdb.MemoryError, StopIteration):
            # print(message.warn('Bad arena address {}'.format(arena_addr.address)))
            return None

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return pwndbg.memory.poi(self.tcache_perthread_struct, tcache_addr)

    def get_heap_boundaries(self, addr=None):
        """Find the boundaries of the heap containing `addr`, default to the
        boundaries of the heap containing the top chunk for the thread's arena.
        """
        region = self.get_region(addr) if addr else self.get_region(self.get_arena()['top'])

        # Occasionally, the [heap] vm region and the actual start of the heap are
        # different, e.g. [heap] starts at 0x61f000 but mp_.sbrk_base is 0x620000.
        # Return an adjusted Page object if this is the case.
        page = pwndbg.memory.Page(0, 0, 0, 0)
        sbrk_base = int(self.mp['sbrk_base'])
        if region == self.get_region(sbrk_base):
            if sbrk_base != region.vaddr:
                page.vaddr = sbrk_base
                page.memsz = region.memsz - (sbrk_base - region.vaddr)
                return page
        return region

    def is_initialized(self):
        addr = pwndbg.symbol.address('__libc_malloc_initialized')
        if addr is None:
            addr = pwndbg.symbol.address('__malloc_initialized')
        return pwndbg.memory.s32(addr) > 0

class HeuristicHeap(Heap):
    def __init__(self):
        super().__init__()
        self._thread_arena_offset = None
    
    @property
    def main_arena(self):
        # TODO/FIXME: These are quite dirty, we should find a better way to do this
        if not self._main_arena_addr:
            if pwndbg.glibc.get_version() < (2, 34):
                malloc_hook_addr = pwndbg.symbol.address('__malloc_hook')
                # Credit: This tricks is modified from https://github.com/hugsy/gef/blob/c530aa518ac96dff6fc810a5552ecf54fd1b3581/gef.py#L1189-L1196
                # Thank @_hugsy_ and all the contributors of gef!
                if pwndbg.arch.current == "x86-64" or pwndbg.arch.current == "i386":
                    self._main_arena_addr = malloc_hook_addr + ((0x20 - (malloc_hook_addr % 0x20)) % 0x20)
                elif pwndbg.arch.current == "aarch64":
                    self._main_arena_addr = malloc_hook_addr - pwndbg.arch.ptrsize * 2 - self.malloc_state(0)._c_struct.__sizeof__()
                elif pwndbg.arch.current == "arm":
                    self._main_arena_addr = malloc_hook_addr - pwndbg.arch.ptrsize - self.malloc_state(0)._c_struct.__sizeof__()
            else: # glibc >= 2.34 does not have __malloc_hook
                # try to find `mstate ar_ptr = &main_arena;` in malloc_trim instructions
                malloc_trim_instructions = pwndbg.disasm.near(pwndbg.symbol.address('malloc_trim'), 10, show_prev_insns=False)
                if pwndbg.arch.current == "x86-64":
                    for instr in malloc_trim_instructions:
                        # try to find `lea rax,[rip+DISP]`
                        if instr.mnemonic == 'lea' and "rip" in instr.op_str and instr.disp > 0:
                            self._main_arena_addr = instr.next + instr.disp # rip + disp
                            break
                elif pwndbg.arch.current == "i386":
                    base_offset = pwndbg.vmmap.find(pwndbg.symbol.address('_IO_list_all')).start
                    for instr in malloc_trim_instructions:
                        # try to find `lea edi,[eax+DISP]`
                        if instr.mnemonic == 'lea' and "eax" in instr.op_str and instr.disp > 0:
                            self._main_arena_addr = base_offset + instr.disp # eax + disp
                            break
                # TODO/FIXME: Add support to arm and aarch64
            # try to search main_arena in .data of libc if we can't find it via above trick
            if not self._main_arena_addr:
                _IO_2_1_stdin_addr = pwndbg.symbol.address('_IO_2_1_stdin_')
                _IO_list_all_addr = pwndbg.symbol.address('_IO_list_all')
                # main_arena is between _IO_2_1_stdin and _IO_list_all
                for addr in range(_IO_2_1_stdin_addr, _IO_list_all_addr, pwndbg.arch.ptrsize):
                    tmp_arena = self.malloc_state(addr)
                    if tmp_arena["next"] == addr:
                        self._main_arena_addr = addr
                        break
                if not self._main_arena_addr:
                    # there are more than one arena, try to find by main_arena.top and main_arena.max_system_mem
                    heap_page = next(x for x in pwndbg.vmmap.get() if "heap]" in x.objfile)
                    for addr in range(_IO_2_1_stdin_addr, _IO_list_all_addr, pwndbg.arch.ptrsize):
                        tmp_arena = self.malloc_state(addr)
                        if heap_page.start <= tmp_arena["top"] <= heap_page.end:
                            if tmp_arena["max_system_mem"] != 0:
                                self._main_arena_addr = addr
                                break

        if self._main_arena_addr:
            self._main_arena = self.malloc_state(self._main_arena_addr)

        return self._main_arena

    def has_tcache(self):
        # TODO/FIXME: Can we determine the tcache_bins existence more reliable?

        # There is no debug symbols, we determine the tcache_bins existence by checking glibc version only
        return self.is_initialized() and pwndbg.glibc.get_version() >= (2, 26)

    @property
    def thread_arena(self):
        if not self._thread_arena_offset:
            # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
            __libc_calloc_instruction = pwndbg.disasm.near(pwndbg.symbol.address('__libc_calloc'), 100, show_prev_insns=False)
            # try to find the reference to thread_arena in arena_get in __libc_calloc ( ptr = thread_arena; )
            if pwndbg.arch.current == "x86-64":
                # try to find something like `mov rax, [rip + disp]`
                # and its next is `mov reg, qword ptr fs:[rax]`
                # and then we can get the tls offset to thread_arena by calculating value of rax

                is_possible = lambda i, instr: __libc_calloc_instruction[i+1].op_str.endswith('qword ptr fs:[rax]') \
                    and instr.op_str.startswith('rax, qword ptr [rip +')
                get_offset_instruction = next(instr for i, instr in enumerate(__libc_calloc_instruction[:-1]) if is_possible(i, instr))
                # rip + disp
                self._thread_arena_offset = pwndbg.memory.s64(get_offset_instruction.next + get_offset_instruction.disp)
            elif pwndbg.arch.current == "i386":
                base_offset = pwndbg.vmmap.find(pwndbg.symbol.address('_IO_list_all')).start
                # try to find something like `mov eax, dword ptr [reg + disp]` (disp is a negative value)
                # and its next is either `mov reg, dword ptr gs:[eax]` or `mov reg, dword ptr [reg + eax]`
                # and then we can get the tls offset to thread_arena by calculating value of eax

                # this part is very dirty, but it works
                is_possible = lambda i, instr: (__libc_calloc_instruction[i+1].op_str.endswith('gs:[eax]') \
                    ^ __libc_calloc_instruction[i+1].op_str.endswith('+ eax]')) \
                    and __libc_calloc_instruction[i+1].mnemonic == 'mov' \
                    and instr.mnemonic == 'mov' \
                    and instr.op_str.startswith('eax, dword ptr [e') \
                    and instr.disp < 0
                get_offset_instruction = [instr for i, instr in enumerate(__libc_calloc_instruction[:-1]) if is_possible(i, instr)][-1]
                # reg + disp (value of reg is the page start of the last libc page)
                self._thread_arena_offset = pwndbg.memory.s32(base_offset + get_offset_instruction.disp)
            # TODO/FIXME: Add support to arm and aarch64
        
        if self._thread_arena_offset:
            if pwndbg.arch.current == "x86-64":
                # fs:[rax]
                return pwndbg.memory.pvoid(pwndbg.regs.fsbase + self._thread_arena_offset)
            elif pwndbg.arch.current == "i386":
                # reg+eax or gs:[eax] (value of reg is gs:[0x0])
                return pwndbg.memory.pvoid(pwndbg.regs.gsbase + self._thread_arena_offset)

        return -1


    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. If it doesn't have one, use the main
        thread's tcache.
        """
        if self.has_tcache():
            # we guess tcache is the first chunk
            arena = self.get_arena()
            heap_region = self.get_heap_boundaries()
            ptr_size = pwndbg.arch.ptrsize
            if arena == self.main_arena:
                cursor = heap_region.start
            else:
                cursor = heap_region.start + self.heap_info.sizeof
                if pwndbg.vmmap.find(self.get_heap(heap_region.start)['ar_ptr']) == heap_region:
                    # Round up to a 2-machine-word alignment after an arena to
                    # compensate for the presence of the have_fastchunks variable
                    # in GLIBC versions >= 2.27.
                    cursor += (self.malloc_state.sizeof + ptr_size) & ~self.malloc_align_mask

            # i686 alignment heuristic
            first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(cursor + ptr_size, ptr_size))
            if first_chunk_size == 0:
                cursor += ptr_size * 2
            
            self._thread_cache = self.tcache_perthread_struct(cursor + ptr_size * 2)

            return self._thread_cache

        else:
            print(message.warn('This version of GLIBC was not compiled with tcache support.'))
            return None

    @property
    def mp(self):
        if not self._mp_addr:
            # try to find mp_ referenced in __libc_free
            # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
            __libc_free_instructions = pwndbg.disasm.near(pwndbg.symbol.address('__libc_free'), 100, show_prev_insns=False)
            if pwndbg.arch.current == "x86-64":
                iter_possible_match = (instr for instr in __libc_free_instructions if instr.mnemonic == 'mov' \
                    and instr.disp > 0 \
                    and instr.op_str.startswith('qword ptr [rip +'))
                try:
                    mp_mmap_threshold_ref = next(iter_possible_match) # mov qword ptr [rip + (mp.mmap_threshold offset)], reg
                    mp_ref = next(iter_possible_match) # mov qword ptr [rip + (mp offset)], reg
                    # references to mp_.mmap_threshold and mp_ are very close to each other
                    while mp_mmap_threshold_ref.next - mp_ref.address > 0x10:
                        mp_mmap_threshold_ref = mp_ref
                        mp_ref = next(iter_possible_match)
                    self._mp_addr = mp_ref.next + mp_ref.disp
                except StopIteration:
                    pass
            elif pwndbg.arch.current == "i386":
                iter_possible_match = (instr for instr in __libc_free_instructions if instr.mnemonic == 'mov' \
                    and instr.disp > 0 \
                    and instr.op_str.startswith('dword ptr ['))
                base_offset = pwndbg.vmmap.find(pwndbg.symbol.address('_IO_list_all')).start
                try:
                    mp_mmap_threshold_ref = next(iter_possible_match) # mov dword ptr [base_offset + (mp.mmap_threshold offset)], reg
                    mp_ref = next(iter_possible_match) # mov dword ptr [base_offset + (mp offset)], reg
                    # references to mp_.mmap_threshold and mp_ are very close to each other
                    while mp_mmap_threshold_ref.next - mp_ref.address > 0x10:
                        mp_mmap_threshold_ref = mp_ref
                        mp_ref = next(iter_possible_match)
                    self._mp_addr = base_offset + mp_ref.disp
                except StopIteration:
                    pass
            # TODO/FIXME: Add support to arm and aarch64
            
            # can't find the reference about mp_ in __libc_free, try to find it with heap boundaries of main_arena
            if not self._mp_addr:
                libc_page = pwndbg.vmmap.find(pwndbg.symbol.address('_IO_list_all'))
                possible_sbrk_base = self.get_heap_boundaries().start
                sbrk_offset = self.malloc_par(0).field_address('sbrk_base')
                # try to search sbrk_base in a part of libc page
                # TODO/FIXME: If mp_.sbrk_base is not same as heap region start, this will fail
                result = pwndbg.search.search(pwndbg.arch.pack(possible_sbrk_base), start=libc_page.start, end=libc_page.end)
                try:
                    self._mp_addr = next(result) - sbrk_offset
                except StopIteration:
                    pass
            

        if self._mp_addr:
            self._mp = self.malloc_par(self._mp_addr)

        return self._mp

    @property
    def global_max_fast(self):
        # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
        if not self._global_max_fast_addr:
            # `__libc_malloc` will call `_int_malloc`, so we try to find the reference to `_int_malloc`
            __libc_malloc_instructions  = pwndbg.disasm.near(pwndbg.symbol.address('__libc_malloc'), 25, show_prev_insns=False)
            _int_malloc_addr = next(instr for instr in __libc_malloc_instructions[5:] if instr.mnemonic == 'call').operands[0].imm
            _int_malloc_instructions = pwndbg.disasm.near(_int_malloc_addr, 25, show_prev_insns=False)
            # there is a reference to global_max_fast in _int_malloc, which is:
            # `if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))`
            if pwndbg.arch.current == "x86-64":
                # cmp qword ptr [rip + global_max_fast_offset], 0x1f
                global_max_fast_ref = next(instr for instr in _int_malloc_instructions if instr.mnemonic == 'cmp' and instr.op_str.startswith('qword ptr [rip +'))
                self._global_max_fast_addr = global_max_fast_ref.next + global_max_fast_ref.disp
            elif pwndbg.arch.current == "i386":
                base_offset = pwndbg.vmmap.find(pwndbg.symbol.address('_IO_list_all')).start
                # cmp reg, [base_offset + global_max_fast_offset]
                global_max_fast_ref = next(instr for instr in _int_malloc_instructions if instr.mnemonic == 'cmp' and 'dword ptr [' in instr.op_str)
                self._global_max_fast_addr = base_offset + global_max_fast_ref.disp
            else:
                # TODO/FIXME: Add support to arm and aarch64

                # return default value to avoid error
                # this might be a problem if you overwrite it with another value
                return 128 if pwndbg.ptrsize == 8 else 64

        if self._global_max_fast_addr:
            self._global_max_fast = pwndbg.memory.u(self._global_max_fast_addr)

        return self._global_max_fast

    @property
    @pwndbg.memoize.reset_on_objfile
    def heap_info(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.HeapInfo

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_chunk(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.MallocChunk

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_state(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.MallocState

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.TcachePerthreadStruct

    @property
    @pwndbg.memoize.reset_on_objfile
    def tcache_entry(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.TcacheEntry

    @property
    @pwndbg.memoize.reset_on_objfile
    def mallinfo(self):
        # TODO/FIXME: Currently, we don't need to create a new class for `struct mallinfo` because we never use it.
        raise NotImplementedError('`struct mallinfo` is not implemented yet.')

    @property
    @pwndbg.memoize.reset_on_objfile
    def malloc_par(self):
        import pwndbg.heap.structs
        return pwndbg.heap.structs.MallocPar

    def get_heap(self, addr):
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        return self.heap_info(heap_for_ptr(addr))

    def get_arena(self, arena_addr=None):
        """Read a malloc_state struct from the specified address, default to
        reading the current thread's arena. Return the main arena if the
        current thread is not attached to an arena.
        """
        if arena_addr is None:
            thread_arena = self.thread_arena
            if self.multithreaded and thread_arena > 0:
                return self.malloc_state(thread_arena)

            return self.main_arena

        return self.malloc_state(arena_addr)

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return self.tcache_perthread_struct(tcache_addr)

    def get_heap_boundaries(self, addr=None):
        """Find the boundaries of the heap containing `addr`, default to the
        boundaries of the heap containing the top chunk for the thread's arena.
        """
        arena = self.get_arena(addr)
        if arena is not None and arena.address > 0:
            region = self.get_region(addr) if addr else self.get_region(self.get_arena()['top'])
        else:
            # If we can't find an arena via heuristics, try to find it via vmmap
            region = next(p for p in pwndbg.vmmap.get() if "heap]" in p.objfile)

        # Occasionally, the [heap] vm region and the actual start of the heap are
        # different, e.g. [heap] starts at 0x61f000 but mp_.sbrk_base is 0x620000.
        # Return an adjusted Page object if this is the case.
        if self._mp_addr:  # sometimes we can't find mp_ via heuristics
            page = pwndbg.memory.Page(0, 0, 0, 0)
            sbrk_base = int(self.mp['sbrk_base'])
            if region == self.get_region(sbrk_base):
                if sbrk_base != region.vaddr:
                    page.vaddr = sbrk_base
                    page.memsz = region.memsz - (sbrk_base - region.vaddr)
                    return page
        return region

    def is_initialized(self):
        # TODO/FIXME: If main_arena['top'] is been modified to 0, this will not work.
        # try to use vmmap or main_arena.top to find the heap
        return any("heap]" in x.objfile for x in pwndbg.vmmap.get()) or self.main_arena['top'] != 0
