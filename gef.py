################################################################################
# GEF - GDB Enhanced Features for Exploiters & Reverse-Engineers
#
# by  @_hugsy_
#
# GEF provides additional functions to GDB using its powerful Python API. Some
# functions were inspired by PEDA (https://github.com/longld/peda) which is totally
# awesome *but* is x86 (32/64bits) specific, whereas GEF supports almost all archs
# supported by GDB.
#
# Notes:
# * Since GEF relies on /proc for mapping addresses in memory or other features, it
#   cannot work on hardened configurations (such as GrSec)
# * GEF supports kernel debugging in a limit way (please report crashes & bugs)
#
# Tested on
# * x86-32/x86-64 (even though you should totally use `gdb-peda` (https://github.com/longld/peda) instead)
# * arm-32/arm-64
# * mips
# * powerpc
# * sparc/sparc64
#
#
# Tested on gdb 7.x / python 2.6 & 2.7 & 3.x
#
# To start: in gdb, type `source /path/to/gef.py`
#
#
# ToDo:
# - add explicit actions for flags (jumps/overflow/negative/etc)
#
# ToDo commands:
# - finish FormatStringSearchCommand
#
#
#

from __future__ import print_function

import math
import struct
import subprocess
import functools
import sys
import re
import tempfile
import os
import binascii
import gdb


if sys.version_info.major == 2:
    import HTMLParser
    import itertools
    from cStringIO import StringIO

    # Compat Py2/3 hacks
    range = xrange

elif sys.version_info.major == 3:
    from html.parser import HTMLParser
    from io import StringIO

    # Compat Py2/3 hack
    long = int
    FileNotFoundError = IOError

else:
    raise Exception("WTF is this Python version??")



__aliases__ = {}
__config__ = {}
NO_COLOR = False


class GefGenericException(Exception):
    def __init__(self, value):
        self.message = value
        return

    def __str__(self):
        return repr(self.message)

class GefMissingDependencyException(GefGenericException): pass
class GefUnsupportedMode(GefGenericException): pass
class GefUnsupportedOS(GefGenericException): pass


# https://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
class memoize(object):
    """Custom Memoize class with resettable cache"""

    def __init__(self, func):
        self.func = func
        self.is_memoized = True
        self.cache = {}
        return

    def __call__(self, *args):
        if args not in self.cache:
            value = self.func(*args)
            self.cache[args] = value
            return value
        return self.func(*args)

    def __repr__(self):
        return self.func.__doc__

    def __get__(self, obj, objtype):
        fn = functools.partial(self.__call__, obj)
        fn.reset = self._reset
        return fn

    def reset(self):
        self.cache = {}
        return


def reset_all_caches():
    for s in dir(sys.modules['__main__']):
        o = getattr(sys.modules['__main__'], s)
        if hasattr(o, "is_memoized") and o.is_memoized:
            o.reset()
    return


# let's get fancy
class Color:
    NORMAL         = "\x1b[0m"
    RED            = "\x1b[31m"
    GREEN          = "\x1b[32m"
    YELLOW         = "\x1b[33m"
    BLUE           = "\x1b[34m"
    BOLD           = "\x1b[1m"
    UNDERLINE      = "\x1b[4m"

    @staticmethod
    def redify(msg): return Color.RED + msg + Color.NORMAL if not NO_COLOR else ""
    @staticmethod
    def greenify(msg): return Color.GREEN + msg + Color.NORMAL if not NO_COLOR else ""
    @staticmethod
    def blueify(msg): return Color.BLUE + msg + Color.NORMAL if not NO_COLOR else ""
    @staticmethod
    def yellowify(msg): return Color.YELLOW + msg + Color.NORMAL if not NO_COLOR else ""
    @staticmethod
    def boldify(msg): return Color.BOLD + msg + Color.NORMAL if not NO_COLOR else ""



# helpers
class Address:
    pass


class Permission:
    READ = 4
    WRITE = 2
    EXECUTE = 1

    def __init__(self, *args, **kwargs):
        self.value = 0
        return

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self.value & Permission.READ else "-"
        perm_str += "w" if self.value & Permission.WRITE else "-"
        perm_str += "x" if self.value & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        p = Permission()
        for arg in args:
            if "READONLY" in arg:
                p.value += Permission.READ
            if "DATA" in arg:
                p.value += Permission.WRITE
            if "CODE" in arg:
                p.value += Permission.EXECUTE
        return p

    @staticmethod
    def from_process_maps(perm_str):
        p = Permission()
        if perm_str[0] == "r":
            p.value += Permission.READ
        if perm_str[1] == "w":
            p.value += Permission.WRITE
        if perm_str[2] == "x":
            p.value += Permission.EXECUTE
        return p


class Section:
    page_start      = None
    page_end        = None
    offset          = None
    permission      = None
    inode           = None
    path            = None

    def __init__(self, *args, **kwargs):
        attrs = ["page_start", "page_end", "offset", "permission", "inode", "path"]
        for attr in attrs:
            value = kwargs[attr] if attr in kwargs else None
            setattr(self, attr, value)
        return


class Zone:
    name              = None
    zone_start        = None
    zone_end          = None
    filename          = None


class Elf:
    e_magic           = None
    e_class           = None
    e_endianness      = None
    e_eiversion       = None
    e_osabi           = None
    e_abiversion      = None
    e_pad             = None
    e_type            = None
    e_machine         = None
    e_version         = None
    e_entry           = None
    e_phoff           = None
    e_shoff           = None
    e_flags           = None
    e_ehsize          = None
    e_phentsize       = None
    e_phnum           = None
    e_shentsize       = None
    e_shnum           = None
    e_shstrndx        = None


def titlify(msg):
    return "{0}[{1} {3} {2}]{0}".format('='*20, Color.RED, Color.NORMAL, msg)

def ok(msg):
    print((Color.BOLD+Color.GREEN+"[+]"+Color.NORMAL+" "+msg))
    return

def warn(msg):
    print((Color.BOLD+Color.YELLOW+"[+]"+Color.NORMAL+" "+msg))
    return

def err(msg):
    print((Color.BOLD+Color.RED+"[+]"+Color.NORMAL+" "+msg))
    return

def info(msg):
    print((Color.BOLD+Color.BLUE+"[+]"+Color.NORMAL+" "+msg))
    return

def hexdump(src, l=0x10, sep='.', show_raw=False):
    res = []

    for i in range(0, len(src), l):
        s = src[i:i+l]
        hexa = ''
        isMiddle = False

        for h in range(0,len(s)):
            if h == l/2:
                hexa += ' '
            h = s[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace('0x','')
            if len(h) == 1:
                h = '0'+h
            hexa += h + ' '

        hexa = hexa.strip(' ')
        text = ''

        for c in s:
            if not isinstance(c, int):
                c = ord(c)
                if 0x20 <= c < 0x7F:
                    text += chr(c)
                else:
                    text += sep

        if show_raw:
            res.append(('%-'+str(l*(2+1)+1)+'s') % (hexa))
        else:
            res.append(('%08X:  %-'+str(l*(2+1)+1)+'s  |%s|') % (i, hexa, text))

    return '\n'.join(res)


def gef_obsolete_function(func):
    def new_func(*args, **kwargs):
        warn("Call to deprecated function {}.".format(func.__name__), category=DeprecationWarning)
        return func(*args, **kwargs)
    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    new_func.__dict__.update(func.__dict__)
    return new_func


def gef_execute(command, as_list = False):

    output = []

    fd, fname = tempfile.mkstemp()
    os.close(fd)

    gdb.execute("set logging file " + fname)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")

    try :
        lines = gdb.execute(command, to_string=True)
        lines = data.splitlines()

        for line in lines:
            address, content = x.split(" ", 1)
            address = long(address.strip()[:-1], 16)
            content = content.strip()

            output.append( (address, content) )

    except:
        pass

    finally:
        gdb.execute("set logging off")
        gdb.execute("set logging redirect off")
        os.unlink(fname)
        return output


def gef_execute_external(command, as_list=False):
    if as_list :
        return subprocess.check_output(command,
                                       stderr=subprocess.STDOUT,
                                       shell=True).splitlines()
    else:
        return subprocess.check_output(command,
                                       stderr=subprocess.STDOUT,
                                       shell=True)


def disassemble_parse(name, filter_opcode=None):
    lines = [x.split(":", 1) for x in gdb_exec("disassemble %s" % name).split('\n') if "0x" in x]
    dis   = []

    for address, opcode in lines:
        try:
            address = address.replace("=>", "  ").strip()
            address = long(address.split(" ")[0], 16)

            i = opcode.find("#")
            if i != -1:
                opcode = opcode[:i]

            i = opcode.find("<")
            if i != -1:
                opcode = opcode[:i]

            opcode = opcode.strip()

            if filter_opcode is None or filter_opcode in opcode:
                dis.append( (address, opcode) )

        except:
            continue

    return dis


def get_frame():
    return gdb.selected_inferior()


def get_arch():
    return gdb.execute("show architecture", to_string=True).strip().split(" ")[7][:-1]


def arm_registers():
    return ["$r0  ", "$r1  ", "$r2  ", "$r3  ", "$r4  ", "$r5  ", "$r6  ",
            "$r7  ", "$r8  ", "$r9  ", "$r10 ", "$r11 ", "$r12 ", "$sp  ",
            "$lr  ", "$pc  ", "$cpsr", ]


def x86_64_registers():
    return [ "$rax   ", "$rcx   ", "$rdx   ", "$rbx   ", "$rsp   ", "$rbp   ", "$rsi   ",
             "$rdi   ", "$rip   ", "$r8    ", "$r9    ", "$r10   ", "$r11   ", "$r12   ",
             "$r13   ", "$r14   ", "$r15   ",
             "$cs    ", "$ss    ", "$ds    ", "$es    ", "$fs    ", "$gs    ", "$eflags", ]


def x86_32_registers():
    return [ "$eax   ", "$ecx   ", "$edx   ", "$ebx   ", "$esp   ", "$ebp   ", "$esi   ",
             "$edi   ", "$eip   ", "$cs    ", "$ss    ", "$ds    ", "$es    ",
             "$fs    ", "$gs    ", "$eflags", ]


def powerpc_registers():
    return ["$r0  ", "$r1  ", "$r2  ", "$r3  ", "$r4  ", "$r5  ", "$r6  ", "$r7  ",
            "$r8  ", "$r9  ", "$r10 ", "$r11 ", "$r12 ", "$r13 ", "$r14 ", "$r15 ",
            "$r16 ", "$r17 ", "$r18 ", "$r19 ", "$r20 ", "$r21 ", "$r22 ", "$r23 ",
            "$r24 ", "$r25 ", "$r26 ", "$r27 ", "$r28 ", "$r29 ", "$r30 ", "$r31 ",
            "$pc  ", "$msr ", "$cr  ", "$lr  ", "$ctr ", "$xer ", "$trap" ]

def sparc_registers():
    return ["$g0 ", "$g1 ", "$g2 ", "$g3 ", "$g4 ", "$g5 ", "$g6 ", "$g7 ",
            "$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ",
            "$l0 ", "$l1 ", "$l2 ", "$l3 ", "$l4 ", "$l5 ", "$l6 ", "$l7 ",
            "$i0 ", "$i1 ", "$i2 ", "$i3 ", "$i4 ", "$i5 ",
            "$pc ", "$sp ", "$fp ", "$psr", ]

def all_registers():
    if is_arm():
        return arm_registers()
    elif is_x86_32():
        return x86_32_registers()
    elif is_x86_64():
        return x86_64_registers()
    elif is_powerpc():
        return powerpc_registers()
    elif is_sparc() or is_sparc64():
        return sparc_registers()
    else:
        raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


def write_memory(address, buffer, length=0x10):
    return gdb.selected_inferior().write_memory(address, buffer, length)


def read_memory(addr, length=0x10):
    if sys.version_info.major == 2:
        return gdb.selected_inferior().read_memory(addr, length)
    else:
        return gdb.selected_inferior().read_memory(addr, length).tobytes()


def read_memory_until_null(address):
    i = 0

    if sys.version_info.major == 2:
        buf = ''
        while True:
            c = read_memory(address + i, 1)[0]
            if c == '\x00': break
            buf += c
            i += 1
        return buf

    else:
        buf = []
        while True:
            c = read_memory(address + i, 1)[0]
            if c == 0x00: break
            buf.append( c )
            i += 1

        return bytes(buf)


def is_readable_string(address):
    """
    Here we will assume that a readable string is
    a consecutive byte array whose
    * last element is 0x00
    * and values for each byte is [0x07, 0x7F]
    """
    buffer = read_memory_until_null(address)
    if len(buffer) == 0:
        return False

    if sys.version_info.major == 2:
        for c in buffer:
            if not (0x07 <= ord(c) < 0x0e) and not (0x20 <= ord(c) < 0x7f):
                return False
    else:
        for c in buffer:
            if not (0x07 <= c < 0x0e) and not (0x20 <= c < 0x7f):
                return False

    return True


def read_string(address):
    if not is_readable_string(address):
        raise ValueError("Content at address `%#x` is not a string" % address)

    buf = read_memory_until_null(address)
    replaced_chars = [ (b"\n",b"\\n"), (b"\r",b"\\r"), (b"\t",b"\\t"), (b"\"",b"\\\"")]
    for f,t in replaced_chars:
        buf = buf.replace(f, t)
    return buf


def is_alive():
    try:
        pid = get_frame().pid
        return pid > 0
    except gdb.error as e:
        return False

    return False


def get_register(regname):
    """
    Get register value. Exception will be raised if expression cannot be parse.
    This function won't catch on purpose.
    @param regname : expected register
    @return register value
    """
    t = gdb.lookup_type("unsigned long")
    reg = gdb.parse_and_eval(regname)
    ret = reg.cast(t)
    return long(ret)


@memoize
def get_pid():
    return get_frame().pid


@memoize
def get_filename():
    return gdb.current_progspace().filename


@memoize
def get_process_maps():
    pid = get_pid()
    sections = []

    try:
        f = open('/proc/%d/maps' % pid)
        while True:
            line = f.readline()
            if len(line) == 0:
                break

            line = line.strip()
            addr, perm, off, dev, rest = line.split(" ", 4)
            rest = rest.split(" ", 1)
            if len(rest) == 1:
                inode = rest[0]
                pathname = ""
            else:
                inode = rest[0]
                pathname = rest[1].replace(' ', '')

            addr_start, addr_end = addr.split("-")
            addr_start, addr_end = long(addr_start, 16), long(addr_end, 16)
            off = long(off, 16)

            perm = Permission.from_process_maps(perm)

            section = Section(page_start  = addr_start,
                              page_end    = addr_end,
                              offset      = off,
                              permission  = perm,
                              inode       = inode,
                              path        = pathname)

            sections.append( section )

    except IOError:
        sections = get_info_sections()

    return sections


@memoize
def get_info_sections():
    sections = []
    stream = StringIO(gdb.execute("maintenance info sections", to_string=True))

    while True:
        line = stream.readline()
        if len(line) == 0:
            break

        line = re.sub('\s+',' ', line.strip())

        try:
            blobs = [x.strip() for x in line.split(' ')]
            index = blobs[0][1:-1]
            addr_start, addr_end = [ long(x, 16) for x in blobs[1].split("->") ]
            at = blobs[2]
            off = long(blobs[3][:-1], 16)
            path = blobs[4]
            inode = ""
            perm = Permission.from_info_sections(blobs[5:])

            section = Section(page_start  = addr_start,
                              page_end    = addr_end,
                              offset      = off,
                              permission  = perm,
                              inode       = inode,
                              path        = path)

            sections.append( section )

        except IndexError:
            continue
        except ValueError:
            continue

    return sections


@memoize
def get_info_files():
    infos = []
    stream = StringIO(gdb.execute("info files", to_string=True))

    while True:
        line = stream.readline()
        if len(line) == 0:
            break

        try:
            blobs = [x.strip() for x in line.split(' ')]
            addr_start = long(blobs[0], 16)
            addr_end = long(blobs[2], 16)
            section_name = blobs[4]

            if len(blobs) == 7:
                filename = blobs[6]
            else:
                filename = get_filename()


        except ValueError:
            continue

        except IndexError:
            continue

        info = Zone()
        info.name = section_name
        info.zone_start = addr_start
        info.zone_end = addr_end
        info.filename = filename

        infos.append( info )

    stream.close()
    return infos


def process_lookup_address(address):
    if not is_alive():
        err("Process is not running")
        return None

    if is_x86_64() or is_x86_32() :
        if is_in_x86_kernel(address):
            return None

    for sect in get_process_maps():
        if sect.page_start <= address <= sect.page_end:
            return sect

    return None


def file_lookup_address(address):
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


def lookup_address(address):
    addr = Address()
    for attr in ["value", "section", "info"]:
        setattr(addr, attr, None)

    addr.value = address

    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return None

    if sect:
        addr.section = sect

    if info:
        addr.info = info

    return addr


def XOR(data, key):
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key)))


# dirty hack, from https://github.com/longld/peda
def define_user_command(cmd, code):
    if sys.version_info.major == 3:
        commands = bytes( "define {0}\n{1}\nend".format(cmd, code), "UTF-8" )
    else:
        commands = "define {0}\n{1}\nend".format(cmd, code)

    fd, fname = tempfile.mkstemp()
    os.write(fd, commands)
    os.close(fd)
    gdb.execute("source %s" % fname)
    os.unlink(fname)
    return


@memoize
def get_elf_headers(filename=None):
    if filename is None:
        filename = get_filename()

    try:
        f = open(filename, "rb")
    except IOError:
        err("'{0}' not found/readable".format(filename))
        return None

    elf = Elf()

    # off 0x0
    elf.e_magic, elf.e_class, elf.e_endianness, elf.e_eiversion = struct.unpack(">IBBB", f.read(7))

    # adjust endianness in bin reading
    if elf.e_endianness == 0x01:
        endian = "<" # LE
    else:
        endian = ">" # BE

    # off 0x7
    elf.e_osabi, elf.e_abiversion = struct.unpack(endian + "BB", f.read(2))
    # off 0x9
    elf.e_pad = f.read(7)
    # off 0x10
    elf.e_type, elf.e_machine, elf.e_version = struct.unpack(endian + "HHI", f.read(8))
    # off 0x18
    if elf.e_class == 0x02: # arch 64bits
        elf.e_entry, elf.e_phoff, elf.e_shoff = struct.unpack(endian + "QQQ", f.read(24))
    else: # arch 32bits
        elf.e_entry, elf.e_phoff, elf.e_shoff = struct.unpack(endian + "III", f.read(12))

    elf.e_flags, elf.e_ehsize, elf.e_phentsize, elf.e_phnum = struct.unpack(endian + "HHHH", f.read(8))
    elf.e_shentsize, elf.e_shnum, elf.e_shstrndx = struct.unpack(endian + "HHH", f.read(6))

    f.close()
    return elf


@memoize
def is_elf64():
    elf = get_elf_headers()
    return elf.e_class == 0x02


@memoize
def is_elf32():
    elf = get_elf_headers()
    return elf.e_class == 0x01

@memoize
def is_x86_64():
    elf = get_elf_headers()
    return elf.e_machine==0x3e

@memoize
def is_x86_32():
    elf = get_elf_headers()
    return elf.e_machine==0x03

@memoize
def is_arm():
    elf = get_elf_headers()
    return elf.e_machine==0x28

@memoize
def is_mips():
    elf = get_elf_headers()
    return elf.e_machine==0x08

@memoize
def is_powerpc():
    elf = get_elf_headers()
    return elf.e_machine==0x14 # http://refspecs.freestandards.org/elf/elfspec_ppc.pdf

@memoize
def is_sparc():
    elf = get_elf_headers()
    return elf.e_machine==0x02

@memoize
def is_sparc():
    elf = get_elf_headers()
    return elf.e_machine==0x12


def get_memory_alignment():
    if is_elf32():
        return 32
    elif is_elf64():
        return 64
    else:
        raise GefUnsupportedMode("GEF is running under an unsupported mode, functions will not work")


def format_address(addr):
    memalign_size = get_memory_alignment()
    if memalign_size == 32:
        return "%#.8x" % (addr & 0xFFFFFFFF)
    elif memalign_size == 64:
        return "%#.16x" % (addr & 0xFFFFFFFFFFFFFFFF)


def clear_screen():
    gdb.execute("shell clear")
    return

def align_address(address):
    if get_memory_alignment()== 32:
        return address & 0xFFFFFFFF
    else:
        return address & 0xFFFFFFFFFFFFFFFF

def is_in_x86_kernel(address):
    address = align_address(address)
    memalign = get_memory_alignment()-1
    return (address >> memalign) == 0xF

#
# breakpoints
#
class FormatStringBreakpoint(gdb.Breakpoint):
    ''' Inspect stack for format string '''
    def __init__(self, spec, num_args):
        super(FormatStringBreakpoint, self).__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        if is_arm():
            regs = ['$r0','$r1','$r2','$3']
            ref = regs[self.num_args]
        else :
            raise NotImplementedError()

        value = gdb.parse_and_eval(ref)
        address = long(value)
        pid = get_pid()

        addr = lookup_address(address)
        if 'w' in addr.permissions:
            print((titlify("Format String Detection")))
            info(">>> Possible writable format string %#x (%s): %s" % (addr, ref, content))
            print((gdb.execute("backtrace")))
            return True

        return False

#
# Functions
#

# credits: http://tromey.com/blog/?p=515
class CallerIs (gdb.Function):
    """Return True if the calling function's name is equal to a string.
    This function takes one or two arguments."""

    def __init__ (self):
        super (CallerIs, self).__init__ ("caller_is")
        return

    def invoke (self, name, nframes = 1):
        frame = gdb.get_current_frame ()
        while nframes > 0:
            frame = frame.get_prev ()
            nframes = nframes - 1
        return frame.get_name () == name.string ()

CallerIs()



#
# Commands
#

class GenericCommand(gdb.Command):
    """Generic class for invoking commands"""

    def __init__(self, *args, **kwargs):
        self.pre_load()

        required_attrs = ["do_invoke", "_cmdline_", "_syntax_"]

        for attr in required_attrs:
            if not hasattr(self, attr):
                raise NotImplemented("Invalid class: missing '%s'" % attr)

        self.__doc__  += "\n" + "Syntax: " + self._syntax_

        command_type = kwargs["command"] if "command" in kwargs else gdb.COMMAND_OBSCURE
        complete_type = kwargs["complete"] if "complete" in kwargs else gdb.COMPLETE_NONE
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, True)
        self.post_load()
        return


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        self.do_invoke(argv)
        return


    def usage(self):
        err("Syntax\n" + self._syntax_ )
        return


    def pre_load(self):
        return


    def post_load(self):
        return


    def add_setting(self, name, value):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        __config__[ key ] = (value, type(value))
        return


    def get_setting(self, name):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        return __config__[ key ][0]


    def del_setting(self, name):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        del ( __config__[ key ] )
        return



# class TemplateCommand(GenericCommand):
    # """TemplaceCommand: add description here."""

    # _cmdline_ = "template-fake"
    # _syntax_  = "%s" % _cmdline_

    # def do_invoke(self, argv):
        # return


class DumpMemoryCommand(GenericCommand):
    """Dump chunks of memory into raw file on the filesystem. Dump file
    name template can be defined in GEF runtime config"""

    _cmdline_ = "dump-memory"
    _syntax_  = "%s LOCATION [SIZE]" % _cmdline_


    def __init__(self):
         super(DumpMemoryCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
         self.add_setting("dumpfile_prefix", "./dumpmem-")
         self.add_setting("dumpfile_suffix", "raw")
         return


    def do_invoke(self, argv):
        argc = len(argv)

        if argc not in (1, 2):
            err("Invalid arguments number")
            self.usage()
            return

        prefix = self.get_setting("dumpfile_prefix")
        suffix = self.get_setting("dumpfile_suffix")

        start_addr = align_address( long(gdb.parse_and_eval( argv[0] )) )
        filename = "%s%#x.%s" % (prefix, start_addr, suffix)
        size = long(argv[1]) if argc==2 and argv[1].isdigit() else 0x100

        with open(filename, "wb") as f:
            mem = read_memory( start_addr, size )
            f.write( mem )

        info("Dumped %d bytes from %#x in '%s'" % (size, start_addr, filename))
        return



class AliasCommand(GenericCommand):
    """GEF defined aliases"""

    _cmdline_ = "gef-alias"
    _syntax_  = "%s (set|show|do|unset)" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc == 0:
            err("Missing action")
            self.usage()
        return

class AliasSetCommand(GenericCommand):
    """GEF add alias command"""
    _cmdline_ = "gef-alias set"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 2:
            err("'%s set' requires at least 2 params")
            return
        alias_name = argv[0]
        alias_cmds  = " ".join(argv[1:]).split(";")

        if alias_name in list( __aliases__.keys() ):
            warn("Replacing alias '%s'" % alias_name)
        __aliases__[ alias_name ] = alias_cmds
        ok("'%s': '%s'" % (alias_name, "; ".join(alias_cmds)))
        return

class AliasUnsetCommand(GenericCommand):
    """GEF remove alias command"""
    _cmdline_ = "gef-alias unset"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if len(argv) != 1:
            err("'%s' requires 1 param" % self._cmdline_)
            return
        if  argv[1] in  __aliases__:
            del __aliases__[ argv[1] ]
        else:
            err("'%s' not an alias" % argv[1])
        return

class AliasShowCommand(GenericCommand):
    """GEF show alias command"""
    _cmdline_ = "gef-alias show"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        for alias_name in list( __aliases__.keys() ):
            print(("'%s'\t'%s'" % (alias_name, ";".join(__aliases__[alias_name]))))
        return

class AliasDoCommand(GenericCommand):
    """GEF do alias command"""
    _cmdline_ = "gef-alias do"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc != 1:
            err("'%s do' requires 1 param")
            return

        alias_name = argv[0]
        if alias_name not in list( __aliases__.keys() ):
            err("No alias '%s'" % alias_name)
            return

        alias_cmds = __aliases__[alias_name]
        for cmd in alias_cmds:
            try:
                if " >> " in cmd:
                    cmd, outfile = cmd.split(" >> ")
                    cmd = cmd.strip()
                    outfile = outfile.strip()

                    with open(outfile, "a") as f:
                        lines_out = gdb.execute(cmd, to_string=True)
                        f.write(lines_out)

                elif " > " in cmd:
                    cmd, outfile = cmd.split(" > ")
                    cmd = cmd.strip()
                    outfile = outfile.strip()

                    with open(outfile, "w") as f:
                        lines_out = gdb.execute(cmd, to_string=True)
                        f.write(lines_out)

                else:
                    gdb.execute(cmd)

            except:
                continue

        return


class SolveKernelSymbolCommand(GenericCommand):
    """Get kernel address"""

    _cmdline_ = "ksymaddr"
    _syntax_  = "%s SymbolToSearch" % _cmdline_

    def do_invoke(self, argv):
        if len(argv) != 1:
            self.usage()
            return

        found = False
        sym = argv[0]
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                try:
                    symaddr, symtype, symname = line.strip().split(" ", 3)
                    symaddr = long(symaddr, 16)
                    if symname == sym:
                        ok("Found matching symbol for '%s' at %#x (type=%s)" % (sym, symaddr, symtype))
                        found = True
                    if sym in symname:
                        warn("Found partial match for '%s' at %#x (type=%s): %s" % (sym, symaddr, symtype, symname))
                        found = True
                except ValueError:
                    pass

        if not found:
            err("No match for '%s'" % sym)
        return


class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "reg"
    _syntax_  = "%s [Register1] [Register2] ... [RegisterN]" % _cmdline_


    def do_invoke(self, argv):
        regs = []

        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) > 0:
            regs = [ reg for reg in all_registers() if reg.strip() in argv ]
        else:
            regs = all_registers()

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            line = Color.boldify(Color.redify(regname)) + ": "

            if str(reg.type) == 'builtin_type_sparc_psr':  # ugly but more explicit
                line+= "%s" % reg

            elif reg.type.code == gdb.TYPE_CODE_FLAGS:
                line+= "%s" % (Color.boldify(str(reg)))

            else:
                addr = align_address( long(reg) )
                line+= Color.boldify(Color.blueify(format_address(addr)))
                addrs = DereferenceCommand.dereference_from(addr)
                if len(addrs) > 1:
                    line+= " -> " + " -> ".join(addrs[1:])
            print(line)

        return


class ShellcodeCommand(GenericCommand):
    """ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to
    download shellcodes"""

    _cmdline_ = "shellcode"
    _syntax_  = "%s (search|get)" % _cmdline_


    def pre_load(self):
        try:
            import requests
        except ImportError:
            raise GefMissingDependencyException("Missing Python `requests` package")
        return


    def do_invoke(self, argv):
        self.usage()
        return


class ShellcodeSearchCommand(GenericCommand):
    """Search patthern in shellcodes database."""

    _cmdline_ = "shellcode search"
    _syntax_  = "%s <pattern1> <pattern2>" % _cmdline_

    api_base = "http://shell-storm.org"
    search_url = api_base + "/api/?s="


    def do_invoke(self, argv):
        if len(argv) == 0:
            err("Missing pattern to search")
            self.usage()
        else:
            self.search_shellcode(argv)
        return


    def search_shellcode(self, search_options):
        requests = sys.modules['requests']

        # API : http://shell-storm.org/shellcode/
        args = "*".join(search_options)
        http = requests.get(self.search_url + args)
        if http.status_code != 200:
            err("Could not query search page: got %d" % http.status_code)
            return

        # format: [author, OS/arch, cmd, id, link]
        lines = http.text.split("\n")
        refs = [ line.split("::::") for line in lines ]

        info("Showing matching shellcodes")
        for ref in refs:
            try:
                auth, arch, cmd, sid, link = ref
                print(("\t".join([sid, arch, cmd])))
            except ValueError:
                continue

        info("Use `%s get <id>` to fetch shellcode" % self._cmdline_)
        return


class ShellcodeGetCommand(GenericCommand):
    """Download shellcode from shellcodes database"""

    _cmdline_ = "shellcode get"
    _syntax_  = "%s <shellcode_id>" % _cmdline_

    api_base = "http://shell-storm.org"
    get_url = api_base + "/shellcode/files/shellcode-%d.php"


    def do_invoke(self, argv):
        if len(argv) != 1:
            err("Missing pattern to search")
            self.usage()
            return

        if not argv[0].isdigit():
            err("ID is not a digit")
            self.usage()
            return

        self.get_shellcode(long(argv[0]))
        return


    def get_shellcode(self, sid):
        requests = sys.modules['requests']

        http = requests.get(self.get_url % sid)
        if http.status_code != 200:
            err("Could not query search page: got %d" % http.status_code)
            return

        info("Downloading shellcode id=%d" % sid)
        fd, fname = tempfile.mkstemp(suffix=".txt", prefix="sc-", text=True, dir='/tmp')
        data = http.text.split("\n")[7:-11]
        buf = "\n".join(data)
        unesc_buf = HTMLParser().unescape( buf )
        os.write(fd, bytes(unesc_buf, "UTF-8"))
        os.close(fd)
        info("Shellcode written as '%s'" % fname)
        return


class CtfExploitTemplaterCommand(GenericCommand):
    """Generates a ready-to-use exploit template for CTF."""

    _cmdline_ = "ctf-exploit-templater"
    _syntax_  = "%s HOST PORT [/path/exploit.py]" % _cmdline_

    def __init__(self):
        super(CtfExploitTemplaterCommand, self).__init__()
        self.add_setting("exploit_path", "./gef-exploit.py")
        return

    def do_invoke(self, argv):
        argc = len(argv)

        if argc not in (2, 3):
            err("%s" % self._syntax_)
            return

        host, port = argv[0], argv[1]
        path = argv[2] if argc==3 else self.get_setting("exploit_path")

        with open(path, "w") as f:
            f.write( CTF_EXPLOIT_TEMPLATE % (host, port) )

        info("Exploit script written as '%s'" % path)
        return


class ROPgadgetCommand(GenericCommand):
    """ROPGadget (http://shell-storm.org/project/ROPgadget) plugin"""

    _cmdline_ = "ropgadget"
    _syntax_  = "%s  [OPTIONS]" % _cmdline_


    def __init__(self):
        super(ROPgadgetCommand, self).__init__()
        return

    def pre_load(self):
        self.add_setting("ropgadget_path", os.getenv("HOME") + "/code/ROPgadget")

        if sys.version_info.major == 3:
            raise GefGenericException("ROPGadget doesn't support Python3 yet")

        ropgadget_path = self.get_setting("ropgadget_path")

        if not os.path.isdir(ropgadget_path):
            self.del_setting( "ropgadget_path" )
            raise GefMissingDependencyException("Failed to import ROPgadget (check path)")

        try:
            sys.path.append( ropgadget_path )
            import ROPgadget

        except ImportError as ie:
            self.del_setting( "ropgadget_path" )
            raise GefMissingDependencyException("Failed to import ROPgadget: %s" % ie)

        return


    def do_invoke(self, argv):
        ROPgadget = sys.modules['ROPgadget']

        class FakeArgs(object):
            binary = None
            string = None
            opcode = None
            memstr = None
            console = None
            norop = None
            nojop = None
            depth = 10
            nosys = None
            range = "0x00-0x00"
            badbytes = None
            only = None
            filter = None
            ropchain = None
            offset = 0x00
            outfile = None
            thumb = None
            rawArch = None
            rawMode = None

        args = FakeArgs()
        self.parse_args(args, argv)
        ROPgadget.Core( args ).analyze()
        return


    def parse_args(self, args, argv):
        info("ROPGadget options")
        # options format is 'option_name1=option_value1'
        for opt in argv:
            name, value = opt.split("=", 1)
            if hasattr(args, name):
                if name == "console":
                    continue
                elif name == "depth":
                    value = long(value)
                    depth = value
                    info("Using depth %d" % depth)
                elif name == "offset":
                    value = long(value, 16)
                    info("Using offset %#x" % value)
                elif name == "range":
                    off_min = long(value.split('-')[0], 16)
                    off_max = long(value.split('-')[1], 16)
                    if off_max < off_min:
                        raise ValueError("Value2 must be higher that Value1")
                    info("Using range [%#x:%#x] (%ld bytes)" % (off_min, off_max, (off_max-off_min)))

                setattr(args, name, value)

        if not hasattr(args, "binary") or getattr(args, "binary") is None:
            setattr(args, "binary", get_filename())

        info("Using binary: %s" % args.binary)
        return


class FileDescriptorCommand(GenericCommand):
    """Enumerate file descriptors opened by process."""

    _cmdline_ = "fd"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        pid = get_pid()
        path = "/proc/%s/fd" % pid

        for fname in os.listdir(path):
            fullpath = path+"/"+fname
            if os.path.islink(fullpath):
                info("- %s -> %s" % (fullpath, os.readlink(fullpath)))

        return


class AssembleCommand(GenericCommand):
    """AssembleCommand: using radare2 to assemble code (requires r2 Python bindings)
    Architecture can be set in GEF runtime config (default is x86).
    Use `list' subcommand to list architectures supported"""

    _cmdline_ = "assemble"
    _syntax_  = "%s (list|instruction1;[instruction2;]...[instructionN;])" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(AssembleCommand, self).__init__()
        self.add_setting("arch", "x86")
        return


    def pre_load(self):
        try:
            import r2, r2.r_asm
        except ImportError:
            raise GefMissingDependencyException("radare2 Python bindings could not be loaded")


    def do_invoke(self, argv):
        if len(argv)==0 or (len(argv)==1 and argv[0]=="list"):
            self.usage()
            err("Modes available:\n%s" % gef_execute_external("rasm2 -L; exit 0"))
            return

        mode = self.get_setting("arch")
        instns = " ".join(argv)
        info( "%s" % self.assemble(mode, instns) )
        return


    def assemble(self, mode, instructions):
        r2 = sys.modules['r2']
        asm = r2.r_asm.RAsm()
        asm.use(mode)
        opcode = asm.massemble( instructions )
        return None if opcode is None else opcode.buf_hex


class InvokeCommand(GenericCommand):
    """InvokeCommand: invoke an external command and display result."""

    _cmdline_ = "invoke"
    _syntax_  = "%s [COMMAND]" % _cmdline_

    def do_invoke(self, argv):
        print(( "%s" % gef_execute_external(" ".join(argv)) ))
        return


class ProcessListingCommand(GenericCommand):
    """List and filter process."""

    _cmdline_ = "ps"
    _syntax_  = "%s [PATTERN]" % _cmdline_

    def __init__(self):
        super(ProcessListingCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("ps_command", "/bin/ps auxww")
        return

    def do_invoke(self, argv):
        processes = self.ps()

        if len(argv) == 0:
            pattern = re.compile("^.*$")
        else:
            pattern = re.compile(argv[0])

        for process in processes:
            command = process['command']

            if not re.search(pattern, command):
                continue

            line = ""
            line += "%s "  % process["user"]
            line += "%d "  % process["pid"]
            line += "%.f " % process["percentage_cpu"]
            line += "%.f " % process["percentage_mem"]
            line += "%s "  % process["tty"]
            line += "%d "  % process["vsz"]
            line += "%s "  % process["stat"]
            line += "%s "  % process["time"]
            line += "%s "  % process["command"]

            print (line)

        return None


    def ps(self):
        processes = list()
        output = gef_execute_external(self.get_setting("ps_command"), True)[1:]

        for line in output:
            field = re.compile('\s+').split(line)

            processes.append({ 'user': field[0],
                               'pid': long(field[1]),
                               'percentage_cpu': eval(field[2]),
                               'percentage_mem': eval(field[3]),
                               'vsz': long(field[4]),
                               'rss': long(field[5]),
                               'tty': field[6],
                               'stat': field[7],
                               'start': field[8],
                               'time': field[9],
                               'command': field[10],
                               'args': field[11:] if len(field) > 11 else ''
                               })

        return processes


class ElfInfoCommand(GenericCommand):
    """Display ELF header informations."""

    _cmdline_ = "elf-info"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        # http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        classes = { 0x01: "32-bit",
                    0x02: "64-bit",
                    }
        endianness = { 0x01: "Little-Endian",
                       0x02: "Big-Endian",
                       }
        osabi = { 0x00: "System V",
                  0x01: "HP-UX",
                  0x02: "NetBSD",
                  0x03: "Linux",
                  0x06: "Solaris",
                  0x07: "AIX",
                  0x08: "IRIX",
                  0x09: "FreeBSD",
                  0x0C: "OpenBSD",
                  }

        types = { 0x01: "Relocatable",
                  0x02: "Executable",
                  0x03: "Shared",
                  0x04: "Core"
                  }

        machines = { 0x02: "SPARC",
                     0x03: "x86",
                     0x08: "MIPS",
                     0x12: "SPARC64",
                     0x14: "PowerPC",
                     0x15: "PowerPC64",
                     0x28: "ARM",
                     0x32: "IA-64",
                     0x3E: "x86-64",
                     0xB7: "AArch64",
                     }

        filename = argv[0] if len(argv) else get_filename()
        elf = get_elf_headers(filename)
        if elf is None:
            return

        data = [("Magic", "{0!s}".format( hexdump(struct.pack(">I",elf.e_magic), show_raw=True))),
                ("Class", "{0:#x} - {1}".format(elf.e_class, classes[elf.e_class])),
                ("Endianness", "{0:#x} - {1}".format(elf.e_endianness, endianness[ elf.e_endianness ])),
                ("Version", "{:#x}".format(elf.e_eiversion)),
                ("OS ABI", "{0:#x} - {1}".format(elf.e_osabi, osabi[ elf.e_osabi])),
                ("ABI Version", "{:#x}".format(elf.e_abiversion)),
                ("Type", "{0:#x} - {1}".format(elf.e_type, types[elf.e_type]) ),
                ("Machine", "{0:#x} - {1}".format(elf.e_machine, machines[elf.e_machine])),
                ("Program Header Table" , "{}".format(format_address(elf.e_phoff))),
                ("Section Header Table" , "{}".format( format_address(elf.e_shoff) )),
                ("Header Table" , "{}".format( format_address(elf.e_phoff))),
                ("ELF Version", "{:#x}".format( elf.e_version)),
                ("Header size" , "{0} ({0:#x})".format(elf.e_ehsize)),
                ("Entry point", "{}".format( format_address(elf.e_entry) )),

                # todo finish
              ]

        for title, content in data:
            print(("{:<30}: {}".format(Color.boldify(title), content)))

        # todo finish
        return


class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it."""

    _cmdline_ = "entry-break"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        # has main() ?
        try:
            value = gdb.parse_and_eval("main")
            info("Breaking at '%s'" % value)
            gdb.execute("tbreak main")
            info("Starting execution")
            gdb.execute("run")
            return

        except gdb.error:
            info("Could not solve `main` symbol")

        # has __libc_start_main() ?
        try:
            value = gdb.parse_and_eval("__libc_start_main")
            info("Breaking at '%s'" % value)
            gdb.execute("tbreak __libc_start_main")
            info("Starting execution")
            gdb.execute("run")
            return

        except gdb.error:
            info("Could not solve `__libc_start_main` symbol")

        ## TODO : add more tests

        # break at entry point - never fail
        elf = get_elf_headers()
        if elf is None:
            return
        value = elf.e_entry
        if value:
            info("Breaking at entry-point: %#x" % value)
            gdb.execute("tbreak *%x" % value)
            info("Starting execution")
            gdb.execute("run")
            return

        return



class ContextCommand(GenericCommand):
    """Display execution context."""

    _cmdline_ = "context"
    _syntax_  = "%s" % _cmdline_

    old_registers = {}

    def __init__(self):
         super(ContextCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
         self.add_setting("show_stack_raw", False)
         self.add_setting("nb_registers_per_line", 4)
         self.add_setting("nb_lines_stack", 5)
         self.add_setting("nb_lines_backtrace", 5)
         self.add_setting("nb_lines_code", 6)
         return


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        # clear_screen()
        self.context_regs()
        self.context_stack()
        self.context_code()
        self.context_trace()

        self.update_registers()

        return

    def context_regs(self):
        print((Color.boldify( Color.blueify("-"*80 + "[regs]") )))
        i = 0
        l = ""

        for reg in all_registers():
            new_value = gdb.parse_and_eval(reg)
            old_value = self.old_registers[reg] if reg in self.old_registers else 0x00

            l += "%s  " % (Color.greenify(reg))
            if new_value.type.code == gdb.TYPE_CODE_FLAGS:
                l += "%s " % (new_value)
            else:
                new_value = align_address( long(new_value) )
                old_value = align_address( long(old_value) )

                if new_value == old_value:
                    l += "%s " % (format_address(new_value))
                else:
                    l += "%s " % Color.redify(format_address(new_value))

            i+=1

            if (i > 0) and (i % self.get_setting("nb_registers_per_line")==0) :
                print(l)
                l = ""

        print("")
        return

    def context_stack(self):
        print (Color.boldify( Color.blueify("-"*80 + "[stack]")))

        show_raw = self.get_setting("show_stack_raw")
        try:
            if show_raw == True:
                mem = read_memory(get_register("$sp"), 0x10 * self.get_setting("nb_lines_stack"))
                print (( hexdump(mem) ))
            else:
                InspectStackCommand.inspect_stack(get_register("$sp"), 10)

        except gdb.MemoryError:
                err("Cannot read memory from $SP (corrupted stack pointer?)")

        return

    def context_code(self):
        print(( Color.boldify( Color.blueify("-"*80 + "[code]")) ))
        try:
            gdb.execute("x/%di $pc" % self.get_setting("nb_lines_code"))
        except gdb.MemoryError:
            err("Cannot disassemble from $PC")
        return

    def context_trace(self):
        print(( Color.boldify( Color.blueify("-"*80 + "[trace]")) ))
        try:
            gdb.execute("backtrace %d" % self.get_setting("nb_lines_backtrace"))
        except gdb.MemoryError:
            err("Cannot backtrace (corrupted frames?)")
        return

    def update_registers(self):
        for reg in all_registers():
            self.old_registers[reg] = gdb.parse_and_eval(reg)
        return



class HexdumpCommand(GenericCommand):
    """Display arranged hexdump (according to architecture endianness) of memory range."""

    _cmdline_ = "xd"
    _syntax_  = "%s (q|d|w|b) LOCATION [SIZE]" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if not is_alive():
            warn("No debugging session active")
            return

        if argc < 2:
            self.usage()
            return

        if argv[0] not in ("q", "d", "w", "b"):
            self.usage()
            return

        fmt = argv[0]
        read_from = align_address( long(gdb.parse_and_eval(argv[1])) )
        read_len = long(argv[2]) if argc>=3 and argv[2].isdigit() else 10

        self._hexdump ( read_from, read_len, fmt )
        return


    def _hexdump(self, start_addr, length, arrange_as):
        elf = get_elf_headers()
        if elf is None:
            return
        endianness = "<" if elf.e_endianness == 0x01 else ">"
        i = 0

        formats = { 'q': ('Q', 8),
                    'd': ('I', 4),
                    'w': ('H', 2),
                    'b': ('B', 1),
                    }
        r, l = formats[arrange_as]
        fmt_str = "<%#x+%x> %#."+str(l*2)+"x"
        fmt_pack = endianness + r

        while i < length:
            cur_addr = start_addr + i*l
            mem = read_memory(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            print (fmt_str % (start_addr, i*l, val))
            i += 1

        return



class DereferenceCommand(GenericCommand):
    """Dereference recursively an address and display information"""

    _cmdline_ = "deref"
    _syntax_  = "%s" % _cmdline_


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) != 1:
            err("Missing argument (register/address)")
            return

        pointer = align_address( long(gdb.parse_and_eval(argv[0])) )
        addrs = DereferenceCommand.dereference_from(pointer)

        print(("Following pointers from `%s`:\n%s: %s" % (argv[0],
                                                          format_address(pointer),
                                                          " -> ".join(addrs))))
        return


    @staticmethod
    def dereference(addr):
        p_long = gdb.lookup_type('unsigned long').pointer()
        return gdb.Value(addr).cast(p_long).dereference()


    @staticmethod
    def dereference_from(addr):
        old_deref = None
        deref = addr
        msg = []
        while True:
            try:

                value = align_address( long(deref) )
                infos = lookup_address(value)
                if infos is None or infos.section is None:
                    msg.append( "%#x" % ( long(deref) ))
                    break

                section = infos.section

                msg.append( "%s" % format_address( long(deref) ))

                if section.permission.value & Permission.EXECUTE:
                    cmd = gdb.execute("x/i %x" % value, to_string=True).replace("=>", '')
                    cmd = re.sub('\s+',' ', cmd.strip())

                    msg.append( "%s" % cmd )
                    break

                elif section.permission.value & Permission.READ:
                    if is_readable_string(value):
                        msg.append( '"%s"' % read_string(value) )
                        break

                old_deref = deref
                deref = DereferenceCommand.dereference(value)

            except Exception as e:
                print(((e)))
                break

        return msg



class ASLRCommand(GenericCommand):
    """View/modify GDB ASLR behavior."""

    _cmdline_ = "aslr"
    _syntax_  = "%s (on|off)" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True)
            i = ret.find("virtual address space is ")
            if i < 0:
                return

            msg = "ASLR is currently "
            if ret[i+25:].strip() == "on.":
                msg+= Color.redify( "disabled" )
            else:
                msg+= Color.green( "enabled" )

            print(("%s" % msg))

            return

        elif argc == 1:
            if argv[0] == "on":
                info("Enabling ASLR")
                gdb.execute("set disable-randomization off")
                return
            elif argv[0] == "off":
                info("Disabling ASLR")
                gdb.execute("set disable-randomization on")
                return

            warn("Invalid command")


        self.usage()
        return



class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data."""

    _cmdline_ = "reset-cache"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        reset_all_caches()
        return



class VMMapCommand(GenericCommand):
    """Display virtual memory mapping"""

    _cmdline_ = "vmmap"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        vmmap = get_process_maps()
        if vmmap is None or len(vmmap)==0:
            err("No address mapping information found")
            return

        if is_elf64():
            print(("%18s %18s %18s %4s %s" % ("Start", "End", "Offset", "Perm", "Path")))
        else:
            print(("%10s %10s %10s %4s %s" % ("Start", "End", "Offset", "Perm", "Path")))
        for entry in vmmap:
            l = []
            l.append( format_address( entry.page_start ))
            l.append( format_address( entry.page_end ))
            l.append( format_address( entry.offset ))

            if entry.permission.value == (Permission.READ|Permission.WRITE|Permission.EXECUTE) :
                l.append( Color.boldify(Color.redify(str(entry.permission))) )
            else:
                l.append( str(entry.permission) )
            l.append( entry.path )

            print((" ".join(l)))
        return


class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary (Truth is out there)."""

    _cmdline_ = "xfiles"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("Debugging session is not active")
            warn("Result may be incomplete (shared libs, etc.)")
            return

        print(("%10s %10s %20s %s" % ("Start", "End", "Name", "File")))
        for xfile in get_info_files():
            l= ""
            l+= "%s %s" % (format_address(xfile.zone_start),
                           format_address(xfile.zone_end))
            l+= "%20s " % xfile.name
            l+= "%s" % xfile.filename
            print (l)
        return


class XAddressInfoCommand(GenericCommand):
    """Get virtual section information for specific address"""

    _cmdline_ = "xinfo"
    _syntax_  = "%s LOCATION" % _cmdline_


    def __init__(self):
         super(XAddressInfoCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
         return


    def do_invoke (self, argv):
        if len(argv) < 1:
            err ("At least one valid address must be specified")
            return

        for sym in argv:
            try:
                addr = align_address( long(gdb.parse_and_eval(sym)) )
                print(( titlify("xinfo: %#x" % addr )))
                self.infos(addr)

            except gdb.error as gdb_err:
                err("Exception raised: %s" % gdb_err)
                continue
        return


    def infos(self, address):
        addr = lookup_address(address)
        if addr is None:
            warn("Cannot reach %#x in memory space" % address)
            return

        sect = addr.section
        info = addr.info

        if sect:
            print(("Found %s" % format_address(addr.value)))
            print(("Page: %s->%s (size=%#x)" % (format_address(sect.page_start),
                                                format_address(sect.page_end),
                                                sect.page_end-sect.page_start)))
            print(("Permissions: %s" % sect.permission))
            print(("Pathname: %s" % sect.path))
            print(("Offset (from page): +%#x" % (address-sect.page_start)))
            print(("Inode: %s" % sect.inode))

        if info:
            print(("Section: %s (%s-%s)" % (info.name,
                                            format_address(info.zone_start),
                                            format_address(info.zone_end))))

        return


class XorMemoryCommand(GenericCommand):
    """XOR a block of memory."""

    _cmdline_ = "xor-memory"
    _syntax_  = "%s (display|patch) <address> <size_to_read> <xor_key> " % _cmdline_


    def do_invoke(self, argv):
        if len(argv) == 0:
            err("Missing subcommand (display|patch)")
            self.usage()
        return

class XorMemoryDisplayCommand(GenericCommand):
    """Display a block of memory by XOR-ing each key with a key."""

    _cmdline_ = "xor-memory display"
    _syntax_  = "%s <address> <size_to_read> <xor_key> " % _cmdline_


    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = long(gdb.parse_and_eval(argv[0]))
        length, key = long(argv[1]), argv[2]
        block = read_memory(address, length)
        info("Displaying XOR-ing %#x-%#x with '%s'" % (address, address+len(block), key))

        print(( titlify("Original block") ))
        print(( hexdump( block ) ))

        print(( titlify("XOR-ed block") ))
        print(( hexdump( XOR(block, key) )))
        return


class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory by XOR-ing each key with a key."""

    _cmdline_ = "xor-memory patch"
    _syntax_  = "%s <address> <size_to_read> <xor_key> " % _cmdline_


    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = long(gdb.parse_and_eval(argv[0]))
        length, key = long(argv[1]), argv[2]
        block = read_memory(address, length)
        info("Patching XOR-ing %#x-%#x with '%s'" % (address, address+len(block), key))

        xored_block = XOR(block, key)
        write_memory(address, xored_block, length)

        return


class TraceRunCommand(GenericCommand):
    """Create a runtime trace of all instructions executed from $pc to LOCATION specified."""

    _cmdline_ = "trace-run"
    _syntax_  = "%s LOCATION [MAX_CALL_DEPTH]" % _cmdline_


    def __init__(self):
        super(TraceRunCommand, self).__init__(self._cmdline_, complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_tracing_recursion", 1)
        self.add_setting("tracefile_prefix", "./gef-trace-")
        return


    def do_invoke(self, argv):
        if len(argv) > 2:
            self.usage()
            return

        if not is_alive():
            warn("Debugging session is not active")
            return

        depth = long(argv[1]) if len(argv)==2 and argv[1].isdigit() else 1

        try:
            loc_start = long(gdb.parse_and_eval("$pc"))
            loc_end = long(gdb.parse_and_eval(argv[0]).address)

        except gdb.error as e:
            err("Invalid location: %s" % e)
            return

        self.trace(loc_start, loc_end)
        return


    def trace(self, loc_start, loc_end):
        info("Tracing from %#x to  %#x" % (loc_start, loc_end))
        logfile = "%s-%#x-%#x.txt" % (self.get_setting("tracefile_prefix"), loc_start, loc_end)

        gdb.execute( "set logging overwrite" )
        gdb.execute( "set logging file %s" % logfile)
        gdb.execute( "set logging redirect on" )
        gdb.execute( "set logging on" )

        self._do_trace(loc_start, loc_end)

        gdb.execute( "set logging redirect off" )
        gdb.execute( "set logging off" )

        info("Formatting output")
        gdb.execute("shell sed -i -e '/^[^0x]/d' -e '/^$/d'  %s" % logfile)
        ok("Done, logfile stored as '%s'" % logfile)
        info("Hint: import logfile with `ida_color_gdb_trace.py` script in IDA to visualize path")
        return


    def _do_trace(self, loc_start, loc_end):
        # todo: add max_depth
        loc_old = 0
        loc_cur = loc_start
        page_mask = 0xFFFF0000

        frame_old = 0
        frame_cur = gdb.selected_frame()

        while is_alive() and loc_cur != loc_end:
            gdb.execute( "nexti" )

        return



class PatternCommand(GenericCommand):
    """Metasploit-like pattern generation/search"""

    _cmdline_ = "pattern"
    _syntax_  = "%s" % _cmdline_


    def do_invoke(self, argv):
        self.usage()
        return


class PatternCreateCommand(GenericCommand):
    """Metasploit-like pattern generation"""

    _cmdline_ = "pattern create"
    _syntax_  = "%s SIZE" % _cmdline_


    def do_invoke(self, argv):
        if len(argv) != 1:
            self.usage()
            return

        if not argv[0].isdigit():
            err("Invalid size")
            return

        size = long(argv[0])
        info("Generating a pattern of %d bytes" % size)
        print(( PatternCreateCommand.generate(size) ))
        return


    @staticmethod
    def generate(limit):
        pattern = ""
        for mj in range(ord('A'), ord('Z')+1) :             # from A to Z
            for mn in range(ord('a'), ord('z')+1) :         # from a to z
                for dg in range(ord('0'), ord('9')+1) :     # from 0 to 9
                    for extra in "~!@#$%&*()-_+={}[]|;:<>?/": # adding extra chars
                        for c in (chr(mj), chr(mn), chr(dg), extra):
                            if len(pattern) == limit :
                                return pattern
                            else:
                                pattern += "%s" % c
        # Should never be here, just for clarity
        return ""


class PatternSearchCommand(GenericCommand):
    """Metasploit-like pattern search"""

    _cmdline_ = "pattern search"
    _syntax_  = "%s SIZE PATTERN" % _cmdline_


    def do_invoke(self, argv):
        if len(argv) != 2:
            self.usage()
            return

        if not argv[0].isdigit():
            err("Invalid size")
            return

        size, pattern = long(argv[0]), argv[1]
        info("Searching in '%s'" % pattern)
        offset = self.search(pattern, size)

        if offset < 0:
            print(("Not found"))

        return


    def search(self, pattern, size):
        try:
            addr = long( gdb.parse_and_eval(pattern) )
            if get_memory_alignment() == 32:
                pattern_be = struct.pack(">I", addr)
                pattern_le = struct.pack("<I", addr)
            else:
                pattern_be = struct.pack(">Q", addr)
                pattern_le = struct.pack("<Q", addr)

        except gdb.error:
            err("Incorrect pattern")
            return -1

        buffer = PatternCreateCommand.generate(size)
        found = False

        off = buffer.find(pattern_le)
        if off >= 0:
            ok("Found at offset %d (little-endian search)" % off)
            found = True

        off = buffer.find(pattern_be)
        if off >= 0:
            ok("Found at offset %d (big-endian search)" % off)
            found = True

        return -1 if not found else 0


class InspectStackCommand(GenericCommand):
    """Exploiter-friendly top-down stack inspection command (peda-like)"""

    _cmdline_ = "inspect-stack"
    _syntax_  = "%s  [NbStackEntry]" % _cmdline_


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        nb_stack_block = 10
        argc = len(argv)
        if argc >= 1:
            try:
                nb_stack_block = long(argv[0])
            except ValueError:
                pass

        top_stack = get_register("$sp")
        self.inspect_stack(top_stack, nb_stack_block)
        return


    @staticmethod
    def inspect_stack(sp, nb_stack_block):
        memalign = get_memory_alignment() >> 3

        for i in range(nb_stack_block):
            cur_addr = align_address( long(sp) + i*memalign )
            addrs = DereferenceCommand.dereference_from(cur_addr)
            msg = Color.boldify(Color.blueify( format_address(cur_addr) ))
            msg += ": "
            msg += " -> ".join(addrs)
            print((msg))

        return




class ChecksecCommand(GenericCommand):
    """Checksec.sh (http://www.trapkit.de/tools/checksec.html) port."""

    _cmdline_ = "checksec"
    _syntax_  = "%s (filename)" % _cmdline_


    def __init__(self):
         super(ChecksecCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
         self.add_setting("readelf_path", "/usr/bin/readelf")
         return


    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            filename = get_filename()

        elif argc == 1:
            filename = argv[0]

        else:
            self.usage()
            return

        if not os.access(self.get_setting("readelf_path"), os.X_OK):
            err("Could not access readelf")

        info("%s for '%s'" % (self._cmdline_, filename))
        self.checksec(filename)
        return


    def do_check(self, title, opt, filename, pattern, is_match):
        options = opt.split(" ")
        buf = "%-50s" % (title+":")
        cmd = [self.get_setting("readelf_path"), ]
        cmd+= options
        cmd+= [filename, ]
        lines = subprocess.check_output( cmd ).split("\n")
        found = False

        for line in lines:
            if re.search(pattern, line):
                buf += Color.GREEN
                if is_match:
                    buf += Color.greenify("Yes")
                else:
                    buf += Color.redify("No")
                found = True
                break

        if not found:
            if is_match:
                buf+= Color.redify("No")
            else:
                buf+= Color.greenify("Yes")

        print(("%s" % buf))
        return


    def checksec(self, filename):
        # check for canary
        self.do_check("Canary", "-s", filename, r'__stack_chk_fail', is_match=True)

        # check for NX
        self.do_check("NX Support", "-W -l", filename, r'GNU_STACK.*RWE', is_match=False)

        # check for PIE support
        self.do_check("PIE Support", "-h", filename, r'Type:.*EXEC', is_match=False)
        # todo : add check for (DEBUG) if .so

        # check for RPATH
        self.do_check("RPATH", "-d -l", filename, r'rpath', is_match=True)

        # check for RUNPATH
        self.do_check("RUNPATH", "-d -l", filename, r'runpath', is_match=True)

        return



class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper (experimental)"""
    _cmdline_ = "fmtstr-helper"
    _syntax_ = "%s" % _cmdline_


    def do_invoke(self, argv):
        dangerous_functions = {
            'printf':     0,
            'sprintf':    1,
            'vfprintf':   1,
            'vsprintf':   1,
            'fprintf':    1,
            'snprintf':   2,
            'vsnprintf':  2,
            }

        for func_name, num_arg in dangerous_functions.iteritems():
            FormatStringBreakpoint(func_name, num_arg)

        return


class GEFCommand(gdb.Command):
    """GEF Control Center"""

    _cmdline_ = "gef"
    _syntax_  = "%s (load/help)" % _cmdline_

    def __init__(self):
        super(GEFCommand, self).__init__(GEFCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT)

        self.classes = [ResetCacheCommand,
                        XAddressInfoCommand,
                        XorMemoryCommand, XorMemoryDisplayCommand, XorMemoryPatchCommand,
                        FormatStringSearchCommand,
                        TraceRunCommand,
                        PatternCommand, PatternSearchCommand, PatternCreateCommand,
                        ChecksecCommand,
                        VMMapCommand,
                        XFilesCommand,
                        ASLRCommand,
                        DereferenceCommand,
                        HexdumpCommand,
                        ContextCommand,
                        EntryPointBreakCommand,
                        ElfInfoCommand,
                        ProcessListingCommand,
                        InvokeCommand,
                        AssembleCommand,
                        FileDescriptorCommand,
                        ROPgadgetCommand,
                        InspectStackCommand,
                        CtfExploitTemplaterCommand,
                        ShellcodeCommand, ShellcodeSearchCommand, ShellcodeGetCommand,
                        DetailRegistersCommand,
                        SolveKernelSymbolCommand,
                        AliasCommand, AliasShowCommand, AliasSetCommand, AliasUnsetCommand, AliasDoCommand,
                        DumpMemoryCommand,

                        # add new commands here
                        ]

        self.__cmds = [ (x._cmdline_, x) for x in self.classes ]
        self.__loaded_cmds = []

        self.load()
        return


    @property
    def loaded_command_names(self):
        return [ x[0] for x in self.__loaded_cmds ]


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) < 1 :
            err("Missing command for gef -- `gef help` for help -- `gef config` for configuring")
            return

        cmd = argv[0]
        if cmd == "help":
            self.help()
        elif cmd == "config":
            self.config(*argv[1:])
        else:
            err("Invalid command '%s' for gef -- type `gef help' for help" % ' '.join(argv))

        return


    def load(self, mod=None):
        for (cmd, class_name) in self.__cmds:
            try:
                class_name()
                self.__loaded_cmds.append( (cmd, class_name)  )
            except Exception as e:
                err("Failed to load `%s`: %s" % (cmd, e))

        print(("%s, `%s' to start, `%s' to configure" % (Color.greenify("gef loaded"),
                                                         Color.redify("gef help"),
                                                         Color.redify("gef config"))))

        ver = "%d.%d" % (sys.version_info.major, sys.version_info.minor)
        nb_cmds = sum([1 for x in self.loaded_command_names if " " not in x])
        nb_sub_cmds = sum([1 for x in self.loaded_command_names if " " in x])
        print(("%s commands loaded (%s sub-commands), using Python engine %s" % (Color.greenify(str(nb_cmds)),
                                                                                 Color.greenify(str(nb_sub_cmds)),
                                                                                 Color.redify(ver))))
        return


    def help(self):
        print((titlify("GEF - GDB Enhanced Features") ))

        for (cmd, class_name) in self.__loaded_cmds:
            if " " in cmd:
                # do not print out subcommands in main help
                continue

            doc = class_name.__doc__ if hasattr(class_name, "__doc__") else ""
            msg = "%-25s -- %s" % (cmd, Color.greenify( doc ))
            print(("%s" % msg))
        return


    def config(self, *args):
        argc = len(args)

        if not (0 <= argc <= 2):
            err("Invalid number of arguments")
            return

        if argc==0 or argc==1:
            config_items = sorted( __config__ )
            plugin_name = args[0] if argc==1 and args[0] in self.loaded_command_names else ""
            print(( titlify("GEF configuration settings %s" % plugin_name) ))
            for key in config_items:
                if plugin_name not in key:
                    continue
                value, type = __config__.get(key, None)
                print( ("%-40s  (%s) = %s" % (key, type.__name__, value)) )
            return

        if "." not in args[0]:
            err("Invalid command format")
            return

        plugin_name, setting_name = args[0].split(".", 1)

        if plugin_name not in self.loaded_command_names:
            err("Unknown plugin '%s'" % plugin_name)
            return

        _curval, _type = __config__.get( args[0], (None, None) )
        if _type == None:
            err("Failed to get '%s' config setting" % (args[0], ))
            return

        try:
            if _type == bool:
                _newval = True if args[1]=="True" else False
            else:
                _newval = args[1]
                _type( _newval )

        except:
            err("%s expects type '%s'" % (args[0], _type.__name__))
            return

        __config__[ args[0] ] = (_newval, _type)
        return





if __name__  == "__main__":
    GEF_PROMPT = Color.boldify(Color.redify("gef> "))

    # setup config
    gdb.execute("set confirm off")
    gdb.execute("set verbose off")
    gdb.execute("set output-radix 0x10")
    gdb.execute("set input-radix 0x10")
    gdb.execute("set height 0")
    gdb.execute("set width 0")
    gdb.execute("set prompt %s" % GEF_PROMPT)
    gdb.execute("set follow-fork-mode child")

    # gdb history
    gdb.execute("set history filename ~/.gdb_history")
    gdb.execute("set history save")

    # aliases
    # WinDBG-like aliases (I like them)

    # breakpoints
    gdb.execute("alias -a bl = info breakpoints")
    gdb.execute("alias -a bp = break")
    gdb.execute("alias -a be = enable breakpoints")
    gdb.execute("alias -a bd = disable breakpoints")
    gdb.execute("alias -a bc = delete breakpoints")
    gdb.execute("alias -a tbp = tbreak")
    gdb.execute("alias -a tba = thbreak")

    # runtime
    gdb.execute("alias -a g = run")

    # memory access
    gdb.execute("alias -a uf = disassemble")

    # context
    gdb.execute("alias -a argv = show args")
    gdb.execute("alias -a kp = info stack")

    try:
        # this will raise a gdb.error unless we're on x86
        # we can safely ignore this
        gdb.execute("set disassembly-flavor intel")
    except gdb.error:
        pass


    # load GEF
    GEFCommand()

    # post-loading stuff
    define_user_command("hook-stop", "context")


################################################################################
##
##  CTF exploit templates
##
CTF_EXPLOIT_TEMPLATE = """#!/usr/bin/env python2
import socket, struct, sys, telnetlib, binascii

HOST = "%s"
PORT = %s

DEBUG = True

def xor(data, key):
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key)))
def hexdump(src, length=0x10):
    f=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    n=0
    result=''
    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%%02X"%%ord(x) for x in s])
       s = s.translate(f)
       result += "%%04X   %%-*s   %%s\\n" %% (n, length*3, hexa, s)
       n+=length
    return result
def i_s(i): return struct.pack("<I", i)
def i_u(i): return struct.unpack("<I", i)[0]
def q_s(i): return struct.pack("<Q", i)
def q_u(i): return struct.unpack("<Q", i)[0]
def h_s(i): return struct.pack("<H", i)
def h_u(i): return struct.unpack("<H", i)[0]
def err(msg): print(("[!] %%s" %% msg))
def ok(msg): print(("[+] %%s" %% msg))
def debug(msg, in_hexa=False):
    if DEBUG:
        if not in_hexa:
            print(("[*] %%s" %% msg))
        else:
            print(("[*] Hexdump:\\n%%s" %% hexdump(msg)))


def grab_banner(s):
    data = s.recv(1024)
    debug("Received %%d bytes: %%s" %% (len(data), data))
    return data

def recv_until(s, pattern="", blocking=False):
    buffer = ""
    while True:
        data = s.recv(1024)
        if data < 0: break
        if data == 0 and not blocking: break
        buffer += data
        if buffer.endswith(pattern): break
    debug("Received %%d bytes until pattern" %% len(buffer))
    return buffer

def build_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    ok("Connected to %%s:%%d" %% (host, port))
    return s

def interact(s):
    t = telnetlib.Telnet()
    t.sock = s
    try:
        t.interact()
    except KeyboardInterrupt:
        ok("Leaving")
    t.close()
    return

def pwn(s):
    #
    # add your l337 stuff here
    #
    return True

if __name__ == "__main__":
    s = build_socket(HOST, PORT)
    banner = grab_banner(s)
    if pwn(s):
        ok("Got it, interacting (Ctrl-C to break)")
        interact(s)
    else:
        err("Failed to exploit")
    exit(0)

# auto-generated by {0}
""".format(__file__)
