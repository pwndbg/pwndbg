"""
The MIT License (MIT)

Copyright (c) 2015 cloudburst

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import print_function
from __future__ import unicode_literals

import struct
import sys
from os import uname

import gdb

# bash color support
color_support = True
if color_support:
    c_red      = "\033[31m"
    c_red_b    = "\033[01;31m"
    c_green    = "\033[32m"
    c_green_b  = "\033[01;32m"
    c_yellow   = "\033[33m"
    c_yellow_b = "\033[01;33m"
    c_blue     = "\033[34m"
    c_blue_b   = "\033[01;34m"
    c_purple   = "\033[35m"
    c_purple_b = "\033[01;35m"
    c_teal     = "\033[36m"
    c_teal_b   = "\033[01;36m"
    c_none     = "\033[0m"
else:
    c_red      = ""
    c_red_b    = ""
    c_green    = ""
    c_green_b  = ""
    c_yellow   = ""
    c_yellow_b = ""
    c_blue     = ""
    c_blue_b   = ""
    c_purple   = ""
    c_purple_b = ""
    c_teal     = ""
    c_teal_b   = ""
    c_none     = ""
c_error  = c_red
c_title  = c_green_b
c_header = c_yellow_b
c_value  = c_blue_b

################################################################################
# MALLOC CONSTANTS AND MACROS
################################################################################

_machine = uname()[4]
if _machine == "x86_64":
    SIZE_SZ = 8
elif _machine in ("i386", "i686"):
    SIZE_SZ = 4

MIN_CHUNK_SIZE    = 4 * SIZE_SZ
MALLOC_ALIGNMENT  = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

def chunk2mem(p):
    "conversion from malloc header to user pointer"
    return (p.address + (2*SIZE_SZ))

def mem2chunk(mem):
    "conversion from user pointer to malloc header"
    return (mem - (2*SIZE_SZ))

def request2size(req):
    "pad request bytes into a usable size"

    if (req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE):
        return MINSIZE
    else:
        return (int(req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)

def prev_inuse(p):
    "extract inuse bit of previous chunk"
    return (p.size & PREV_INUSE)

def chunk_is_mmapped(p):
    "check for mmap()'ed chunk"
    return (p.size & IS_MMAPPED)

def chunk_non_main_arena(p):
    "check for chunk from non-main arena"
    return (p.size & NON_MAIN_ARENA)

def chunksize(p):
    "Get size, ignoring use bits"
    return (p.size & ~SIZE_BITS)

def next_chunk(p):
    "Ptr to next physical malloc_chunk."
    return (p.address + (p.size & ~SIZE_BITS))

def prev_chunk(p):
    "Ptr to previous physical malloc_chunk"
    return (p.address - p.prev_size)

def chunk_at_offset(p, s):
    "Treat space at ptr + offset as a chunk"
    return malloc_chunk(p.address + s, inuse=False)

def inuse(p):
    "extract p's inuse bit"
    return (malloc_chunk(p.address + \
            (p.size & ~SIZE_BITS), inuse=False).size & PREV_INUSE)

def set_inuse(p):
    "set chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse(p):
    "clear chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def inuse_bit_at_offset(p, s):
    "check inuse bits in known places"
    return (malloc_chunk((p.address + s), inuse=False).size & PREV_INUSE)

def set_inuse_bit_at_offset(p, s):
    "set inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse_bit_at_offset(p, s):
    "clear inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def bin_at(m, i):
    "addressing -- note that bin_at(0) does not exist"
    if SIZE_SZ == 4:
        offsetof_fd = 0x8
        return (gdb.parse_and_eval("&main_arena.bins[%d]" % \
            ((i -1) * 2)).cast(gdb.lookup_type('unsigned int')) - offsetof_fd)
    elif SIZE_SZ == 8:
        offsetof_fd = 0x10
        return (gdb.parse_and_eval("&main_arena.bins[%d]" % \
            ((i -1) * 2)).cast(gdb.lookup_type('unsigned long')) - offsetof_fd)

def next_bin(b):
    return (b + 1)

def first(b):
    return b.fd

def last(b):
    return b.bk

NBINS          = 128
NSMALLBINS     = 64
SMALLBIN_WIDTH = MALLOC_ALIGNMENT
MIN_LARGE_SIZE = (NSMALLBINS * SMALLBIN_WIDTH)

def in_smallbin_range(sz):
    "check if size is in smallbin range"
    return (sz < MIN_LARGE_SIZE)

def smallbin_index(sz):
    "return the smallbin index"

    if SMALLBIN_WIDTH == 16:
        return (sz >> 4)
    else:
        return (sz >> 3)

def largebin_index_32(sz):
    "return the 32bit largebin index"

    if (sz >> 6) <= 38:
        return (56 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index_64(sz):
    "return the 64bit largebin index"

    if (sz >> 6) <= 48:
        return (48 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index(sz):
    "return the largebin index"

    if SIZE_SZ == 8:
        return largebin_index_64(sz)
    else:
        return largebin_index_32(sz)

def bin_index(sz):
    "return the bin index"

    if in_smallbin_range(sz):
        return smallbin_index(sz)
    else:
        return largebin_index(sz)

BINMAPSHIFT = 5
BITSPERMAP  = 1 << BINMAPSHIFT
BINMAPSIZE  = (NBINS / BITSPERMAP)

def fastbin(ar_ptr, idx):
    return ar_ptr.fastbinsY[idx]

def fastbin_index(sz):
    "offset 2 to use otherwise unindexable first 2 bins"
    if SIZE_SZ == 8:
        return ((sz >> 4) - 2)
    else:
        return ((sz >> 3) - 2)

MAX_FAST_SIZE = (80 * SIZE_SZ / 4)
NFASTBINS     = (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

FASTCHUNKS_BIT = 0x1

def have_fastchunks(M):
    return ((M.flags & FASTCHUNKS_BIT) == 0)

def clear_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

NONCONTIGUOUS_BIT = 0x2

def contiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) == 0)

def noncontiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) != 0)

def set_noncontiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_contiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def get_max_fast():
    return gdb.parse_and_eval("global_max_fast")

def mutex_lock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 1
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))

def mutex_unlock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 0
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print(c_error + "No gdb inferior could be found." + c_none)
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print(c_error + "This gdb's python support is too old." + c_none)
        exit()


################################################################################
class malloc_chunk:
    "python representation of a struct malloc_chunk"

    def __init__(self,addr=None,mem=None,size=None,inferior=None,inuse=False,read_data=True):
        self.prev_size   = 0
        self.size        = 0
        self.data        = None
        self.fd          = None
        self.bk          = None
        self.fd_nextsize = None
        self.bk_nextsize = None

        if addr == None or addr == 0:
            if mem == None:
                sys.stdout.write(c_error)
                print("Please specify a valid struct malloc_chunk address.", end=' ')
                sys.stdout.write(c_none)
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x8)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x10)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None
        else:
            # a string of raw memory was provided
            if inuse:
                if (len(mem)!=0x8) and (len(mem)<0x10):
                    sys.stdout.write(c_error)
                    print("Insufficient memory provided for a malloc_chunk.", end=' ')
                    sys.stdout.write(c_none)
                    return None
                if len(mem)==0x8 or len(mem)==0x10:
                    #header only provided
                    read_data = False
            else:
                if (len(mem)!=0x18) and (len(mem)<0x30):
                    sys.stdout.write(c_error)
                    print("Insufficient memory provided for a free chunk.", end=' ')
                    sys.stdout.write(c_none)
                    return None

        if SIZE_SZ == 4:
            (self.prev_size,
            self.size) = struct.unpack_from("<II", mem, 0x0)
        elif SIZE_SZ == 8:
            (self.prev_size,
            self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if size == None:
            real_size = (self.size & ~SIZE_BITS)
        else:
            #a size was provided (for a malformed chunk with an invalid size)
            real_size = size & ~SIZE_BITS

        if inuse:
            if read_data:
                if self.address != None:
                    # a string of raw memory was not provided
                    try:
                        mem = inferior.read_memory(addr, real_size + SIZE_SZ)
                    except TypeError:
                        print(c_error + "Invalid address specified." + c_none)
                        return None
                    except RuntimeError:
                        print(c_error + "Could not read address 0x%x" % addr \
                                + c_none)
                        return None

                real_size = (real_size - SIZE_SZ) / SIZE_SZ
                if SIZE_SZ == 4:
                    self.data = struct.unpack_from("<%dI" % real_size, mem, 0x8)
                elif SIZE_SZ == 8:
                    self.data = struct.unpack_from("<%dQ" %real_size, mem, 0x10)

        if not inuse:
            if self.address != None:
                # a string of raw memory was not provided
                if inferior != None:
                    if SIZE_SZ == 4:
                        mem = inferior.read_memory(addr, 0x18)
                    elif SIZE_SZ == 8:
                        mem = inferior.read_memory(addr, 0x30)

            if SIZE_SZ == 4:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<IIII", mem, 0x8)
            elif SIZE_SZ == 8:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<QQQQ", mem, 0x10)

    def write(self, inferior=None):
        if self.fd == None and self.bk == None:
            inuse = True
        else:
            inuse = False

        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if inuse:
            if SIZE_SZ == 4:
                mem = struct.pack("<II", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dI" % len(self.data), *self.data)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQ", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dQ" % len(self.data), *self.data)
        else:
            if SIZE_SZ == 4:
                mem = struct.pack("<IIIIII", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQQQQQ", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        if self.prev_size == 0 and self.size == 0:
            return ""
        elif self.fd == None and self.bk == None:
            ret =  "%s%s%x%s%x%s" %                               \
                    (c_title + "struct malloc_chunk {",           \
                    c_none + "\nprev_size   = " + c_value + "0x", \
                    self.prev_size,                               \
                    c_none + "\nsize        = " + c_value + "0x", \
                    self.size, c_none)

            if self.data != None:
                if SIZE_SZ == 4:
                    ret += "%s%s%r" %                                       \
                            ("\ndata        = " + c_value + str(self.data), \
                            c_none + "\nraw         = " + c_value,          \
                            struct.pack("<%dI"%len(self.data), *self.data))
                elif SIZE_SZ == 8:
                    ret += "%s%s%r" %                                       \
                            ("\ndata        = " + c_value + str(self.data), \
                            c_none + "\nraw         = " + c_value,          \
                            struct.pack("<%dQ"%len(self.data), *self.data))
                ret += c_none

            return ret
        else:
            return "%s%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" %           \
                    (c_title + "struct malloc_chunk {",           \
                    c_none + "\nprev_size   = " + c_value + "0x", \
                    self.prev_size,                               \
                    c_none + "\nsize        = " + c_value + "0x", \
                    self.size,                                    \
                    c_none + "\nfd          = " + c_value + "0x", \
                    self.fd,                                      \
                    c_none + "\nbk          = " + c_value + "0x", \
                    self.bk,                                      \
                    c_none + "\nfd_nextsize = " + c_value + "0x", \
                    self.fd_nextsize,                             \
                    c_none + "\nbk_nextsize = " + c_value + "0x", \
                    self.bk_nextsize, c_none)

################################################################################
class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.mutex          = 0
        self.flags          = 0
        self.fastbinsY      = 0
        self.top            = 0
        self.last_remainder = 0
        self.bins           = 0
        self.binmap         = 0
        self.next           = 0
        self.system_mem     = 0
        self.max_system_mem = 0

        if addr == None:
            if mem == None:
                sys.stdout.write(c_error)
                print("Please specify a struct malloc_state address.")
                sys.stdout.write(c_none)
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x44c)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x880)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None

        if SIZE_SZ == 4:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10I", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<II", mem, 0x30)

            self.bins            = struct.unpack_from("<254I", mem, 0x38)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x430)
            (self.next,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<III", mem, 0x440)
        elif SIZE_SZ == 8:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10Q", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            self.bins            = struct.unpack_from("<254Q", mem, 0x68)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x858)
            (self.next,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<QQQ", mem, 0x868)

    def write(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if SIZE_SZ == 4:
            mem = struct.pack("<275I", self.mutex, self.flags, self.fastbinsY, \
                    self.top, self.last_remainder, self.bins, self.binmap, \
                    self.next, self.system_mem, self.max_system_mem)
        elif SIZE_SZ == 8:
            mem = struct.pack("<II266QIIIIQQQ", self.mutex, self.flags, \
                    self.fastbinsY, self.top, self.last_remainder, self.bins, \
                    self.binmap, self.next, self.system_mem, \
                    self.max_system_mem)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        return "%s%s%x%s%x%s%s%lx%s%lx%s%s%s%lx%s%lx%s%lx%s" %      \
                (c_title + "struct malloc_state {",                 \
                c_none + "\nmutex          = " + c_value + "0x",    \
                self.mutex,                                         \
                c_none + "\nflags          = " + c_value + "0x",    \
                self.flags,                                         \
                c_none + "\nfastbinsY      = " + c_value + "{...}", \
                c_none + "\ntop            = " + c_value + "0x",    \
                self.top,                                           \
                c_none + "\nlast_remainder = " + c_value + "0x",    \
                self.last_remainder,                                \
                c_none + "\nbins           = " + c_value + "{...}", \
                c_none + "\nbinmap         = " + c_value + "{...}", \
                c_none + "\nnext           = " + c_value + "0x",    \
                self.next,                                          \
                c_none + "\nsystem_mem     = " + c_value + "0x",    \
                self.system_mem,                                    \
                c_none + "\nmax_system_mem = " + c_value + "0x",    \
                self.max_system_mem, c_none)


################################################################################
class malloc_par:
    "python representation of a struct malloc_par"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.trim_threshold   = 0
        self.top_pad          = 0
        self.mmap_threshold   = 0
        self.n_mmaps          = 0
        self.n_mmaps_max      = 0
        self.max_n_mmaps      = 0
        self.no_dyn_threshold = 0
        self.mmapped_mem      = 0
        self.max_mmapped_mem  = 0
        self.max_total_mem    = 0
        self.sbrk_base        = 0

        if addr == None:
            if mem == None:
                sys.stdout.write(c_error)
                print("Please specify a struct malloc_par address.")
                sys.stdout.write(c_none)
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x2c)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x58)
            except TypeError:
                print(c_error + "Invalid address specified." + c_none)
                return None
            except RuntimeError:
                print(c_error + "Could not read address 0x%x" % addr + c_none)
                return None

        if SIZE_SZ == 4:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<11I", mem)
        elif SIZE_SZ == 8:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<11Q", mem)

    def __str__(self):
        return "%s%s%lx%s%lx%s%lx%s%x%s%x%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" % \
                (c_title + "struct malloc_par {",                  \
                c_none + "\ntrim_threshold   = " + c_value + "0x", \
                self.trim_threshold,                               \
                c_none + "\ntop_pad          = " + c_value + "0x", \
                self.top_pad,                                      \
                c_none + "\nmmap_threshold   = " + c_value + "0x", \
                self.mmap_threshold,                               \
                c_none + "\nn_mmaps          = " + c_value + "0x", \
                self.n_mmaps,                                      \
                c_none + "\nn_mmaps_max      = " + c_value + "0x", \
                self.n_mmaps_max,                                  \
                c_none + "\nmax_n_mmaps      = " + c_value + "0x", \
                self.max_n_mmaps,                                  \
                c_none + "\nno_dyn_threshold = " + c_value + "0x", \
                self.no_dyn_threshold,                             \
                c_none + "\nmmapped_mem      = " + c_value + "0x", \
                self.mmapped_mem,                                  \
                c_none + "\nmax_mmapped_mem  = " + c_value + "0x", \
                self.max_mmapped_mem,                              \
                c_none + "\nmax_total_mem    = " + c_value + "0x", \
                self.max_total_mem,                                \
                c_none + "\nsbrk_base        = " + c_value + "0x", \
                self.sbrk_base,                                    \
                c_none)



################################################################################
# ARENA CONSTANTS AND MACROS
################################################################################

HEAP_MIN_SIZE     = 32 * 1024
HEAP_MAX_SIZE     = 1024 * 1024

def top(ar_ptr):
    return ar_ptr.top

def heap_for_ptr(ptr):
    "find the heap and corresponding arena for a given ptr"
    return (ptr & ~(HEAP_MAX_SIZE-1))


################################################################################
# GDB PRETTY PRINTERS
################################################################################

class malloc_par_printer:
    "pretty print the malloc parameters (mp_)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%lx%s%lx%s%lx%s%x%s%x%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" % \
                (c_title + "struct malloc_par {",                  \
                c_none + "\ntrim_threshold   = " + c_value + "0x", \
                self.val['trim_threshold'],                        \
                c_none + "\ntop_pad          = " + c_value + "0x", \
                self.val['top_pad'],                               \
                c_none + "\nmmap_threshold   = " + c_value + "0x", \
                self.val['mmap_threshold'],                        \
                c_none + "\nn_mmaps          = " + c_value + "0x", \
                self.val['n_mmaps'],                               \
                c_none + "\nn_mmaps_max      = " + c_value + "0x", \
                self.val['n_mmaps_max'],                           \
                c_none + "\nmax_n_mmaps      = " + c_value + "0x", \
                self.val['max_n_mmaps'],                           \
                c_none + "\nno_dyn_threshold = " + c_value + "0x", \
                self.val['no_dyn_threshold'],                      \
                c_none + "\nmmapped_mem      = " + c_value + "0x", \
                self.val['mmapped_mem'],                           \
                c_none + "\nmax_mmapped_mem  = " + c_value + "0x", \
                self.val['max_mmapped_mem'],                       \
                c_none + "\nmax_total_mem    = " + c_value + "0x", \
                self.val['max_total_mem'],                         \
                c_none + "\nsbrk_base        = " + c_value + "0x", \
                self.val['sbrk_base'],                             \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class malloc_state_printer:
    "pretty print a struct malloc_state (ar_ptr)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%x%s%x%s%s%lx%s%lx%s%s%s%lx%s%lx%s%lx%s" %      \
                (c_title + "struct malloc_state {",                 \
                c_none + "\nmutex          = " + c_value + "0x",    \
                self.val['mutex'],                                  \
                c_none + "\nflags          = " + c_value + "0x",    \
                self.val['flags'],                                  \
                c_none + "\nfastbinsY      = " + c_value + "{...}", \
                c_none + "\ntop            = " + c_value + "0x",    \
                self.val['top'],                                    \
                c_none + "\nlast_remainder = " + c_value + "0x",    \
                self.val['last_remainder'],                         \
                c_none + "\nbins           = " + c_value + "{...}", \
                c_none + "\nbinmap         = " + c_value + "{...}", \
                c_none + "\nnext           = " + c_value + "0x",    \
                self.val['next'],                                   \
                c_none + "\nsystem_mem     = " + c_value + "0x",    \
                self.val['system_mem'],                             \
                c_none + "\nmax_system_mem = " + c_value + "0x",    \
                self.val['max_system_mem'],                         \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class malloc_chunk_printer:
    "pretty print a struct malloc_chunk"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" %           \
                (c_title + "struct malloc_chunk {",           \
                c_none + "\nprev_size   = " + c_value + "0x", \
                self.val['prev_size'],                        \
                c_none + "\nsize        = " + c_value + "0x", \
                self.val['size'],                             \
                c_none + "\nfd          = " + c_value + "0x", \
                self.val['fd'],                               \
                c_none + "\nbk          = " + c_value + "0x", \
                self.val['bk'],                               \
                c_none + "\nfd_nextsize = " + c_value + "0x", \
                self.val['fd_nextsize'],                      \
                c_none + "\nbk_nextsize = " + c_value + "0x", \
                self.val['bk_nextsize'],                      \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class heap_info_printer:
    "pretty print a struct heap_info"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%lx%s%lx%s%lx%s%lx%s" %                     \
                (c_title + "struct heap_info {",                \
                c_none + "\nar_ptr        = " + c_value + "0x", \
                self.val['ar_ptr'],                             \
                c_none + "\nprev          = " + c_value + "0x", \
                self.val['prev'],                               \
                c_none + "\nsize          = " + c_value + "0x", \
                self.val['size'],                               \
                c_none + "\nmprotect_size = " + c_value + "0x", \
                self.val['mprotect_size'],                      \
                c_none)

    def display_string(self):
        return "string"

################################################################################
def pretty_print_heap_lookup(val):
    "Look-up and return a pretty-printer that can print val."

    # Get the type.
    type = val.type

    # If it points to a reference, get the reference.
    if type.code == gdb.TYPE_CODE_REF:
        type = type.target()

    # Get the unqualified type, stripped of typedefs.
    type = type.unqualified().strip_typedefs()

    # Get the type name.
    typename = type.tag
    if typename == None:
        return None
    elif typename == "malloc_par":
        return malloc_par_printer(val)
    elif typename == "malloc_state":
        return malloc_state_printer(val)
    elif typename == "malloc_chunk":
        return malloc_chunk_printer(val)
    elif typename == "_heap_info":
        return heap_info_printer(val)
    else:
        print(typename)

    # Cannot find a pretty printer.  Return None.
    return None


################################################################################
# GDB COMMANDS
################################################################################

class print_malloc_stats(gdb.Command):
    "print general malloc stats, adapted from malloc.c mSTATs()"

    def __init__(self):
        super(print_malloc_stats, self).__init__("print_mstats",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_mstats main_arena=0x12345"

        try:
            mp         = gdb.selected_frame().read_var('mp_')

            if arg.find("main_arena") == -1:
                main_arena = gdb.selected_frame().read_var('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            sys.stdout.write(c_error)
                            print("Malformed main_arena parameter")
                            sys.stdout.write(c_none)
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            sys.stdout.write(c_error)
            print("No frame is currently selected.")
            sys.stdout.write(c_none)
            return
        except ValueError:
            sys.stdout.write(c_error)
            print("Debug glibc was not found.")
            sys.stdout.write(c_none)
            return

        if main_arena_address == 0:
            sys.stdout.write(c_error)
            print("Invalid main_arena address (0)")
            sys.stdout.write(c_none)
            return

        in_use_b = mp['mmapped_mem']
        system_b = in_use_b

        arena = 0
        while(1):
            ar_ptr = malloc_state(main_arena_address)
            mutex_lock(ar_ptr)

            sys.stdout.write(c_title)
            print("=================================", end=' ')
            print("Malloc Stats =================================\n")
            sys.stdout.write(c_none)

            # account for top
            avail = chunksize(malloc_chunk(top(ar_ptr), inuse=True, \
                    read_data=False))
            nblocks = 1

            nfastblocks = 0
            fastavail = 0

            # traverse fastbins
            for i in range(NFASTBINS):
                p = fastbin(ar_ptr, i)
                while p!=0:
                    p = malloc_chunk(p, inuse=False)
                    nfastblocks += 1
                    fastavail += chunksize(p)
                    p = p.fd

            avail += fastavail

            # traverse regular bins
            for i in range(1, NBINS):
                b = bin_at(ar_ptr, i)
                p = malloc_chunk(first(malloc_chunk(b,inuse=False)),inuse=False)

                while p.address != b:
                    nblocks += 1
                    avail += chunksize(p)
                    p = malloc_chunk(first(p), inuse=False)

            sys.stdout.write(c_header)
            print("Arena %d:" % arena)
            sys.stdout.write(c_none)
            print(c_none + "system bytes     = " + \
                    c_value + "0x%x" % ar_ptr.system_mem)
            print(c_none + "in use bytes     = " + \
                    c_value + "0x%x\n" % (ar_ptr.system_mem - avail))

            system_b += ar_ptr.system_mem
            in_use_b += (ar_ptr.system_mem - avail)

            mutex_unlock(ar_ptr)
            if ar_ptr.next == main_arena_address:
                break
            else:
                ar_ptr = malloc_state(ar_ptr.next)
                arena += 1

        print(c_header + "Total (including mmap):")
        print(c_none + "system bytes     = " + c_value + "0x%x" % system_b)
        print(c_none + "in use bytes     = " + c_value + "0x%x" % in_use_b)
        print(c_none + "max system bytes = " + \
                c_value + "0x%x" % mp['max_total_mem'])
        print(c_none + "max mmap regions = " + \
                c_value + "0x%x" % mp['max_n_mmaps'])
        print(c_none + "max mmap bytes   = " + \
                c_value + "0x%lx" % mp['max_mmapped_mem'] + c_none)


################################################################################
class heap(gdb.Command):
    "print a comprehensive view of the heap"

    def __init__(self):
        super(heap, self).__init__("heap", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Usage can be obtained via heap -h"

        inferior = get_inferior()
        if inferior == -1:
            return

        if arg.find("-h") != -1:
            print(c_title + "==============================", end=' ')
            print("Heap Dump Help ==================================\n" + c_none)

            print(c_title + "Options:\n" + c_none)
            print(c_header + "  -a 0x1234" + c_none \
                    + "\tSpecify an arena address")
            print(c_header + "  -b" + c_none + \
                    "\t\tPrint compact bin listing (only free chunks)")
            print(c_header + "  -c" + c_none + \
                    "\t\tPrint compact arena listing (all chunks)")
            print(c_header + "  -f [#]" + c_none + \
                    "\tPrint all fast bins, or only a single fast bin")
            print(c_header + "  -l" + c_none + \
                    "\t\tPrint a flat listing of all chunks in an arena")
            print(c_header + "  -s [#]" + c_none + \
                    "\tPrint all small bins, or only a single small bin\n")
            return

        a_found = f_found = s_found = p_fb = p_sb = p_b = p_l = p_c = 0
        for item in arg.split():
            if a_found == 1:
                arena_address = int(item,16)
                a_found = 0
                continue
            if f_found == 1:
                f_found = 0
                try:
                    fb_number = int(item)
                except:
                    pass
                continue
            if s_found == 1:
                s_found = 0
                try:
                    sb_number = int(item)
                except:
                    pass
                continue
            if item.find("-a") != -1:
                a_found = 1
            if item.find("f") != -1:
                f_found = 1
                fb_number = None
                p_fb = 1
            if item.find("s") != -1:
                s_found = 1
                sb_number = None
                p_sb = 1
            if item.find("b") != -1:
                p_b = 1
            if item.find("l") != -1:
                p_l = 1
            if item.find("c") != -1:
                p_c = 1

        if arg.find("-a") == -1:
            try:
                main_arena = gdb.selected_frame().read_var('main_arena')
                arena_address = main_arena.address
            except RuntimeError:
                print(c_error + "No gdb frame is currently selected." + c_none)
                return
            except ValueError:
                print(c_error + "Debug glibc was not found, " \
                    "guessing main_arena address via offset from libc." + c_none)

                #find heap by offset from end of libc in /proc
                libc_end,heap_begin = read_proc_maps(inferior.pid)

                if SIZE_SZ == 4:
                    #__malloc_initialize_hook + 0x20
                    #offset seems to be +0x380 on debug glibc, +0x3a0 otherwise
                    arena_address = libc_end + 0x3a0
                elif SIZE_SZ == 8:
                    #offset seems to be +0xe80 on debug glibc, +0xea0 otherwise
                    arena_address = libc_end + 0xea0

                if libc_end == -1:
                    print(c_error + "Invalid address read via /proc" + c_none)
                    return

        if arena_address == 0:
            print(c_error + "Invalid arena address (0)" + c_none)
            return

        ar_ptr = malloc_state(arena_address)

        if len(arg) == 0:
            if ar_ptr.next == 0:
                print("%s%s %s 0x%x) %s" % (c_error, \
                        "ERROR: No arenas could be correctly guessed.", \
                        "(Nothing was found at", ar_ptr.address, c_none))
                return

            print(c_title + "==================================", end=' ')
            print("Heap Dump ===================================\n" + c_none)

            print(c_title + "Arena(s) found:" + c_none)
            try: #arena address obtained via read_var
                print("\t arena @ 0x%x" % \
                        ar_ptr.address.cast(gdb.lookup_type("unsigned long")))
            except: #arena address obtained via -a
                print("\t arena @ 0x%x" % ar_ptr.address)

            if ar_ptr.address != ar_ptr.next:
                #we have more than one arena

                curr_arena = malloc_state(ar_ptr.next)
                while (ar_ptr.address != curr_arena.address):
                    print("\t arena @ 0x%x" % curr_arena.address)
                    curr_arena = malloc_state(curr_arena.next)

                    if curr_arena.address == 0:
                        print(c_error + \
                           "ERROR: No arenas could be correctly found." + c_none)
                        break #breaking infinite loop

            print("")
            return

        try:
            fb_base = ar_ptr.address.cast(gdb.lookup_type("unsigned long")) + 8
        except:
            fb_base = ar_ptr.address + 8
        if SIZE_SZ == 4:
            try:
                sb_base=ar_ptr.address.cast(gdb.lookup_type("unsigned long"))+56
            except:
                sb_base = ar_ptr.address + 56
        elif SIZE_SZ == 8:
            try:
                sb_base = ar_ptr.address.cast(gdb.lookup_type("unsigned long"))\
                        + 104
            except:
                sb_base = ar_ptr.address + 104

        try:
            mp_ = gdb.selected_frame().read_var('mp_')
            mp_address = mp_.address
        except RuntimeError:
            print(c_error + "No gdb frame is currently selected." + c_none)
            return
        except ValueError:
            print(c_error + "Debug glibc was not found, " \
                   "guessing mp_ address via offset from main_arena." + c_none)

            if SIZE_SZ == 4:
                try:
                    mp_address = ar_ptr.address.cast(gdb.lookup_type(\
                                                    "unsigned long")) + 0x460
                except:
                    mp_address = ar_ptr.address + 0x460
            elif SIZE_SZ == 8: #offset 0x880 untested on 64bit
                try:
                    mp_address = ar_ptr.address.cast(gdb.lookup_type(\
                                                    "unsigned long")) + 0x880
                except:
                    mp_address = ar_ptr.address + 0x460
        sbrk_base = malloc_par(mp_address).sbrk_base

        if p_fb:
            print_fastbins(inferior, fb_base, fb_number)
            print("")
        if p_sb:
            print_smallbins(inferior, sb_base, sb_number)
            print("")
        if p_b:
            print_bins(inferior, fb_base, sb_base)
            print("")
        if p_l:
            print_flat_listing(ar_ptr, sbrk_base)
            print("")
        if p_c:
            print_compact_listing(ar_ptr, sbrk_base)
            print("")


############################################################################
def read_proc_maps(pid):
    '''
    Locate the stack of a process using /proc/pid/maps.
    Will not work on hardened machines (grsec).
    '''

    filename = '/proc/%d/maps' % pid

    try:
        fd = open(filename)
    except IOError:
        print(c_error + "Unable to open %s" % filename + c_none)
        return -1,-1

    found = libc_begin = libc_end = heap_begin = heap_end = 0
    for line in fd:
        if line.find("libc-") != -1:
            fields = line.split()

            libc_begin,libc_end = fields[0].split('-')
            libc_begin = int(libc_begin,16)
            libc_end = int(libc_end,16)
        elif line.find("heap") != -1:
            fields = line.split()

            heap_begin,heap_end= fields[0].split('-')
            heap_begin = int(heap_begin,16)
            heap_end = int(heap_end,16)

    fd.close()

    if libc_begin==0 or libc_end==0:
        print(c_error+"Unable to read libc address information via /proc"+c_none)
        return -1,-1

    if heap_begin==0 or heap_end==0:
        print(c_error+"Unable to read heap address information via /proc"+c_none)
        return -1,-1

    return libc_end,heap_begin


################################################################################
def print_fastbins(inferior, fb_base, fb_num):
    "walk and print the fast bins"

    print(c_title + "===================================", end=' ')
    print("Fastbins ===================================\n" + c_none)

    for fb in range(0,NFASTBINS):
        if fb_num != None:
            fb = fb_num

        offset = fb_base + fb*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, SIZE_SZ)
            if SIZE_SZ == 4:
                fd = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                fd = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print(c_error + " ERROR: Invalid fb addr 0x%lx" % offset + c_none)
            return

        print("%s%s%d%s%s0x%08lx%s%s%s0x%08lx%s%s" % \
                (c_header,"[ fb  ",fb," ] ",c_none,offset,\
                 " -> ",c_value,"[ ",fd," ]",c_none), end=' ')

        if fd == 0: #fastbin is empty
            print("")
        else:
            fb_size = ((MIN_CHUNK_SIZE) +(MALLOC_ALIGNMENT)*fb)
            print("(%d)" % fb_size)
            chunk = malloc_chunk(fd, inuse=False)
            while chunk.fd != 0:
                if chunk.fd is None:   # could not read memory section
                    break
                print("%s%26s0x%08lx%s%s(%d)" % (c_value,"[ ",chunk.fd," ] ",c_none, fb_size))
                chunk = malloc_chunk(chunk.fd, inuse=False)

        if fb_num != None: #only print one fastbin
            return


################################################################################
def print_smallbins(inferior, sb_base, sb_num):
    "walk and print the small bins"

    print(c_title + "===================================", end=' ')
    print("Smallbins ==================================\n" + c_none)

    for sb in range(2,NBINS+2,2):
        if sb_num != None and sb_num!=0:
            sb = sb_num*2

        offset = sb_base + (sb-2)*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, 2*SIZE_SZ)
            if SIZE_SZ == 4:
                fd,bk = struct.unpack("<II", mem)
            elif SIZE_SZ == 8:
                fd,bk = struct.unpack("<QQ", mem)
        except RuntimeError:
            print(c_error + " ERROR: Invalid sb addr 0x%lx" % offset + c_none)
            return

        print("%s%s%02d%s%s0x%08lx%s%s%s0x%08lx%s0x%08lx%s%s" % \
                            (c_header,"[ sb ",sb/2," ] ",c_none,offset, \
                            " -> ",c_value,"[ ", fd, " | ", bk, " ] ",  \
                            c_none))

        while (1):
            if fd == (offset-2*SIZE_SZ):
                break

            chunk = malloc_chunk(fd, inuse=False)
            print("%s%26s0x%08lx%s0x%08lx%s%s" % \
                    (c_value,"[ ",chunk.fd," | ",chunk.bk," ] ",c_none), end=' ')
            print("(%d)" % chunksize(chunk))

            fd = chunk.fd

        if sb_num != None: #only print one smallbin
            return


################################################################################
def print_bins(inferior, fb_base, sb_base):
    "walk and print the nonempty free bins, modified from jp"

    print(c_title + "==================================", end=' ')
    print("Heap Dump ===================================\n" + c_none)

    for fb in range(0,NFASTBINS):
        print_once = True
        p = malloc_chunk(fb_base-(2*SIZE_SZ)+fb*SIZE_SZ, inuse=False)

        while (p.fd != 0):
            if p.fd is None:
                break

            if print_once:
                print_once = False
                print(c_header + "  fast bin %d   @ 0x%lx" % \
                        (fb,p.fd) + c_none)
            print("    free chunk @ " + c_value + "0x%lx" % p.fd + c_none + \
                  " - size" + c_value, end=' ')
            p = malloc_chunk(p.fd, inuse=False)
            print("0x%lx" % chunksize(p) + c_none)

    for i in range(1, NBINS):
        print_once = True
        b = sb_base + i*2*SIZE_SZ - 4*SIZE_SZ
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)

        while p.address != b:
            if print_once:
                print_once = False
                if i==1:
                    try:
                        print(c_header + "  unsorted bin @ 0x%lx" % \
                          (b.cast(gdb.lookup_type("unsigned long")) \
                          + 2*SIZE_SZ) + c_none)
                    except:
                        print(c_header + "  unsorted bin @ 0x%lx" % \
                          (b + 2*SIZE_SZ) + c_none)
                else:
                    try:
                        print(c_header + "  small bin %d @ 0x%lx" %  \
                         (i,b.cast(gdb.lookup_type("unsigned long")) \
                         + 2*SIZE_SZ) + c_none)
                    except:
                        print(c_header + "  small bin %d @ 0x%lx" % \
                         (i,b + 2*SIZE_SZ) + c_none)

            print(c_none + "    free_chunk @ " + c_value \
                  + "0x%lx " % p.address + c_none        \
                  + "- size " + c_value + "0x%lx" % chunksize(p) + c_none)

            p = malloc_chunk(first(p), inuse=False)


################################################################################
def print_flat_listing(ar_ptr, sbrk_base):
    "print a flat listing of an arena, modified from jp and arena.c"

    print(c_title + "==================================", end=' ')
    print("Heap Dump ===================================\n" + c_none)
    print("%s%14s%17s%15s%s" % (c_header, "ADDR", "SIZE", "STATUS", c_none))
    print("sbrk_base " + c_value + "0x%lx" % sbrk_base)

    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        print("%schunk     %s0x%-14lx 0x%-10lx%s" % \
                (c_none, c_value, p.address, chunksize(p), c_none), end=' ')

        if p.address == top(ar_ptr):
            print("(top)")
            break
        elif p.size == (0|PREV_INUSE):
            print("(fence)")
            break

        if inuse(p):
            print("%s" % "(inuse)")
        else:
            p = malloc_chunk(p.address, inuse=False)
            print("(F) FD %s0x%lx%s BK %s0x%lx%s" % \
                    (c_value, p.fd, c_none,c_value,p.bk,c_none), end=' ')

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                print("(LR)")
            elif ((p.fd == p.bk) & ~inuse(p)):
                print("(LC)")
            else:
                print("")

        p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)

    print(c_none + "sbrk_end  " + c_value \
            + "0x%lx" % (sbrk_base + ar_ptr.system_mem) + c_none)


################################################################################
def print_compact_listing(ar_ptr, sbrk_base):
    "print a compact layout of the heap, modified from jp"

    print(c_title + "==================================", end=' ')
    print("Heap Dump ===================================" + c_none)
    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        if p.address == top(ar_ptr):
            sys.stdout.write("|T|\n")
            break

        if inuse(p):
            sys.stdout.write("|A|")
        else:
            p = malloc_chunk(p.address, inuse=False)

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                sys.stdout.write("|L|")
            else:
                sys.stdout.write("|%d|" % bin_index(p.size))

        p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)


################################################################################
class print_bin_layout(gdb.Command):
    "dump the layout of a free bin"

    def __init__(self):
        super(print_bin_layout, self).__init__("print_bin_layout",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_bin_layout main_arena=0x12345"

        if len(arg) == 0:
            sys.stdout.write(c_error)
            print("Please specify the free bin to dump")
            sys.stdout.write(c_none)
            return

        try:
            if arg.find("main_arena") == -1:
                main_arena = gdb.selected_frame().read_var('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            sys.stdout.write(c_error)
                            print("Malformed main_arena parameter")
                            sys.stdout.write(c_none)
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            sys.stdout.write(c_error)
            print("No frame is currently selected.")
            sys.stdout.write(c_none)
            return
        except ValueError:
            sys.stdout.write(c_error)
            print("Debug glibc was not found.")
            sys.stdout.write(c_none)
            return

        if main_arena_address == 0:
            sys.stdout.write(c_error)
            print("Invalid main_arena address (0)")
            sys.stdout.write(c_none)
            return

        ar_ptr = malloc_state(main_arena_address)
        mutex_lock(ar_ptr)

        sys.stdout.write(c_title)
        print("=================================", end=' ')
        print("Bin Layout ===================================\n")
        sys.stdout.write(c_none)

        b = bin_at(ar_ptr, int(arg))
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)
        print_once = True
        print_str  = ""
        count      = 0

        while p.address != b:
            if print_once:
                print_once=False
                print_str += "-->  " + c_value + "[bin %d]" % int(arg) + c_none
                count += 1

            print_str += "  <-->  " + c_value + "0x%lx" % p.address + c_none
            count += 1
            #print_str += "  <-->  0x%lx" % p.address
            p = malloc_chunk(first(p), inuse=False)

        if len(print_str) != 0:
            print_str += "  <--"
            print(print_str)
            print("%s%s%s" % ("|"," " * (len(print_str) - 2 - count*12),"|"))
            print("%s" % ("-" * (len(print_str) - count*12)))
        else:
            print("Bin %d empty." % int(arg))

        mutex_unlock(ar_ptr)


################################################################################
class check_house_of_mind(gdb.Command):
    "print and help validate a house of mind layout"

    def __init__(self):
        super(check_house_of_mind, self).__init__("check_house_of_mind",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        """
        Specify the house of mind method and chunk address (p=mem2chunk(mem)):
        check_house_of_mind method=unsortedbin p=0x12345678
        check_house_of_mind method=fastbin p=0x12345678
        """

        if arg.find("method") == -1:
            print("Please specify the House of Mind method to use:")
            print("house_of_mind method={unsortedbin, fastbin}")
            return
        elif arg.find("p") == -1:
            print("Please specify the chunk address to use:")
            print("house_of_mind p=0x12345678")
            return
        else:
            arg = arg.split()
            for item in arg:
                if item.find("method") != -1:
                    if len(item) < 8:
                        sys.stdout.write(c_error)
                        print("Malformed method parameter")
                        print("Please specify the House of Mind method to use:")
                        print("house_of_mind method={unsortedbin, fastbin}")
                        sys.stdout.write(c_none)
                        return
                    else:
                        method = item[7:]
                if item.find("p") != -1:
                    if len(item) < 11:
                        sys.stdout.write(c_error)
                        print("Malformed chunk parameter")
                        print("Please specify the chunk address to use:")
                        print("house_of_mind p=0x12345678")
                        sys.stdout.write(c_none)
                        return
                    else:
                        p = int(item[2:],16)

        sys.stdout.write(c_title)
        print("===============================", end=' ')
        print("House of Mind ==================================\n")
        sys.stdout.write(c_none)

        if method.find("unsorted") != -1:
            self.unsorted_bin_method(p)
        elif method.find("fast") != -1:
            self.fast_bin_method(p)

    def unsorted_bin_method(self, p):
        p = malloc_chunk(addr=p, inuse=True, read_data=False)

        print(c_none + "Checking chunk p")
        print(c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none)

        if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
            print(" [*] size does not wrap")
        else:
            print(c_error + " [_] ERROR: p > -size" + c_none)
            return

        if chunksize(p) >= MINSIZE:
            print(" [*] size is > minimum chunk size")
        else:
            print(c_error + " [_] ERROR: chunksize(p) < MINSIZE" + c_none)
            return

        if chunksize(p) > get_max_fast():
            print(" [*] size is not in fastbin range")
        else:
            print(c_error + " [_] ERROR: size is in fastbin range" + c_none)
            return

        if not chunk_is_mmapped(p):
            print(" [*] is_mmapped bit is not set")
        else:
            print(c_error + " [_] ERROR: IS_MMAPPED bit is set" + c_none)
            return

        if prev_inuse(p):
            print(" [*] prev_inuse bit is set")
        else:
            print(c_error + " [_] ERROR: PREV_INUSE bit is not set, this will", end=' ')
            print("trigger backward consolidation" + c_none)

        if chunk_non_main_arena(p):
            print(" [*] non_main_arena flag is set")
        else:
            print(c_error + " [_] ERROR: p's non_main_arena flag is NOT set")
            return

        print(c_none + "\nChecking struct heap_info")
        print(c_none + " [*] struct heap_info = " \
                + c_value + "0x%x" % heap_for_ptr(p.address))

        inferior = get_inferior()
        if inferior == -1:
            return None

        try:
            mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
            if SIZE_SZ == 4:
                ar_ptr = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                ar_ptr = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print(c_error + " [_] ERROR: Invalid heap_info address 0x%x" \
                    % heap_for_ptr(p.address) + c_none)
            return

        print(c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr)
        print(c_none + "\nChecking struct malloc_state")

        #test malloc_state address
        try:
            mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
        except RuntimeError:
            print(c_error + " [_] ERROR: Invalid malloc_state address 0x%x" % \
                    ar_ptr + c_none)
            return

        av = malloc_state(ar_ptr)

        if av.mutex == 0:
            print(c_none + " [*] av->mutex is zero")
        else:
            print(c_error + " [_] ERROR: av->mutex is not zero" + c_none)
            return

        if p.address != av.top:
            print(c_none + " [*] p is not the top chunk")
        else:
            print(c_error + " [_] ERROR: p is the top chunk" + c_none)
            return

        if noncontiguous(av):
            print(c_none + " [*] noncontiguous_bit is set")
        elif contiguous(av):
            print(c_error + \
                " [_] ERROR: noncontiguous_bit is NOT set in av->flags" + c_none)
            return

        print(" [*] bck = &av->bins[0] = " + c_value + "0x%x" % (ar_ptr+0x38))

        if SIZE_SZ == 4:
            print(c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 8) =", end=' ')
        elif SIZE_SZ == 8:
            print(c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 16) =", end=' ')

        fwd = inferior.read_memory(ar_ptr + 0x38 + 2*SIZE_SZ, SIZE_SZ)
        if SIZE_SZ == 4:
            fwd = struct.unpack("<I", fwd)[0]
        elif SIZE_SZ == 8:
            fwd = struct.unpack("<Q", fwd)[0]
        print(c_value + "0x%x" % fwd)

        if fwd != (ar_ptr+0x38):
            print(c_none + " [!] fwd->bk (0x%x) != bck (0x%x)" % \
                    (fwd, ar_ptr+0x38) + c_error)
            print("     - ERROR: This will prevent this attack on glibc 2.11+", end=' ')
            print(c_none)

        print(c_none + "\nChecking following chunks")
        nextchunk = chunk_at_offset(p, chunksize(p))

        if prev_inuse(nextchunk):
            print(c_none + " [*] prev_inuse of the next chunk is set")
        else:
            print(c_error + " [_] PREV_INUSE bit of the next chunk is not set" \
                    + c_none)
            return

        if chunksize(nextchunk) > 2*SIZE_SZ:
            print(c_none + " [*] nextchunk size is > minimum size")
        else:
            print(c_error + " [_] ERROR: nextchunk size (%d) < %d" % \
                    (chunksize(nextchunk), 2*SIZE_SZ) + c_none)
            return

        if chunksize(nextchunk) < av.system_mem:
            print(c_none + " [*] nextchunk size is < av->system_mem")
        else:
            print(c_error + " [_] ERROR: nextchunk size (0x%x) >" % \
                    chunksize(nextchunk), end=' ')
            print("av->system_mem (0x%x)" % av.system_mem + c_none)
            return

        if nextchunk.address != av.top:
            print(c_none + " [*] nextchunk != av->top")
        else:
            print(c_error + " [_] ERROR: nextchunk is av->top (0x%x)" % av.top \
                    + c_none)
            return

        if inuse_bit_at_offset(nextchunk, chunksize(nextchunk)):
            print(c_none + " [*] prev_inuse bit set on chunk after nextchunk")
        else:
            print(c_error + " [_] ERROR: PREV_INUSE bit of chunk after", end=' ')
            print("nextchunk (0x%x) is not set" % \
                    (nextchunk.address + chunksize(nextchunk)) + c_none)
            return

        print(c_header + "\np (0x%x) will be written to fwd->bk (0x%x)" \
                % (p.address, fwd+0xC) + c_none)

    def fast_bin_method(self, p):
        p = malloc_chunk(addr=p, inuse=True, read_data=False)

        print(c_none + "Checking chunk p")
        print(c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none)

        if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
            print(" [*] size does not wrap")
        else:
            print(c_error + " [_] ERROR: p > -size" + c_none)
            return

        if chunksize(p) >= MINSIZE:
            print(" [*] size is >= minimum chunk size")
        else:
            print(c_error + " [_] ERROR: chunksize(p) < MINSIZE" + c_none)
            return

        if chunksize(p) < get_max_fast():
            print(" [*] size is in fastbin range")
        else:
            print(c_error + " [_] ERROR: size is not in fastbin range" + c_none)
            return

        if chunk_non_main_arena(p):
            print(" [*] non_main_arena flag is set")
        else:
            print(c_error + " [_] ERROR: p's non_main_arena flag is NOT set")
            return

        if prev_inuse(p):
            print(" [*] prev_inuse bit is set")
        else:
            print(c_error + " [_] ERROR: PREV_INUSE bit is not set, this will", end=' ')
            print("trigger backward consolidation" + c_none)

        print(c_none + "\nChecking struct heap_info")
        print(c_none + " [*] struct heap_info = " \
                + c_value + "0x%x" % heap_for_ptr(p.address))

        inferior = get_inferior()
        if inferior == -1:
            return None

        try:
            mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
            if SIZE_SZ == 4:
                ar_ptr = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                ar_ptr = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print(c_error + " [_] ERROR: Invalid heap_info address 0x%x" \
                    % heap_for_ptr(p.address) + c_none)
            return

        print(c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr)
        print(c_none + "\nChecking struct malloc_state")

        #test malloc_state address
        try:
            mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
        except RuntimeError:
            print(c_error + " [_] ERROR: Invalid malloc_state address 0x%x" % \
                    ar_ptr + c_none)
            return

        av = malloc_state(ar_ptr)

        if av.mutex == 0:
            print(c_none + " [*] av->mutex is zero")
        else:
            print(c_error + " [_] ERROR: av->mutex is not zero" + c_none)
            return

        print(c_none + " [*] av->system_mem is 0x%x" % av.system_mem)

        print(c_none + "\nChecking following chunk")
        nextchunk = chunk_at_offset(p, chunksize(p))
        print(" [*] nextchunk = " + c_value + "0x%x" % nextchunk.address)

        if nextchunk.size > 2*SIZE_SZ:
            print(c_none + " [*] nextchunk size is > 2*SIZE_SZ")
        else:
            print(c_error + " [_] ERROR: nextchunk size is <= 2*SIZE_SZ" +c_none)
            return

        if chunksize(nextchunk) < av.system_mem:
            print(c_none + " [*] nextchunk size is < av->system_mem")
        else:
            print(c_error + " [_] ERROR: nextchunk size (0x%x) is >= " % \
                    chunksize(nextchunk), end=' ')
            print("av->system_mem (0x%x)" % (av.system_mem) + c_none)
            return

        fb = ar_ptr + (2*SIZE_SZ) + (fastbin_index(p.size)*SIZE_SZ)
        print(c_header + "\np (0x%x) will be written to fb (0x%x)" \
                % (p.address, fb) + c_none)


################################################################################
# INITIALIZE CUSTOM GDB CODE
################################################################################

heap()
print_malloc_stats()
print_bin_layout()
check_house_of_mind()
gdb.pretty_printers.append(pretty_print_heap_lookup)
