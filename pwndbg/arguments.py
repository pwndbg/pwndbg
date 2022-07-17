#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Allows describing functions, specifically enumerating arguments which
may be passed in a combination of registers and stack values.
"""
import gdb
from capstone import CS_GRP_CALL
from capstone import CS_GRP_INT

import pwndbg.abi
import pwndbg.arch
import pwndbg.chain
import pwndbg.color.nearpc as N
import pwndbg.constants
import pwndbg.disasm
import pwndbg.funcparser
import pwndbg.functions
import pwndbg.ida
import pwndbg.memory
import pwndbg.regs
import pwndbg.symbol
import pwndbg.typeinfo

ida_replacements = {
    '__int64': 'signed long long int',
    '__int32': 'signed int',
    '__int16': 'signed short',
    '__int8': 'signed char',
    '__uint64': 'unsigned long long int',
    '__uint32': 'unsigned int',
    '__uint16': 'unsigned short',
    '__uint8': 'unsigned char',
    '_BOOL_1': 'unsigned char',
    '_BOOL_2': 'unsigned short',
    '_BOOL_4': 'unsigned int',
    '_BYTE': 'unsigned char',
    '_WORD': 'unsigned short',
    '_DWORD': 'unsigned int',
    '_QWORD': 'unsigned long long',
    '__pure': '',
    '__hidden': '',
    '__return_ptr': '',
    '__struct_ptr': '',
    '__array_ptr': '',
    '__fastcall': '',
    '__cdecl': '',
    '__thiscall': '',
    '__userpurge': '',
}


def get_syscall_name(instruction):
    if CS_GRP_INT not in instruction.groups:
        return None

    try:
        abi     = pwndbg.abi.ABI.syscall()
        syscall = getattr(pwndbg.regs, abi.syscall_register)
        name    = pwndbg.constants.syscall(syscall)

        return 'SYS_' + name
    except:
        return None


def get(instruction):
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call' or 'bl' type instruction.

    Otherwise, returns None.
    """
    n_args_default = 4

    if instruction.address != pwndbg.regs.pc:
        return []

    try:
        abi = pwndbg.abi.ABI.default()
    except KeyError:
        return []

    if CS_GRP_CALL in instruction.groups:
        # Not sure of any OS which allows multiple operands on
        # a call instruction.
        assert len(instruction.operands) == 1

        target = instruction.operands[0].int

        if not target:
            return []

        name = pwndbg.symbol.get(target)
        if not name:
            return []
    elif CS_GRP_INT in instruction.groups:
        # Get the syscall number and name
        abi = pwndbg.abi.ABI.syscall()

        target  = None
        syscall = getattr(pwndbg.regs, abi.syscall_register)
        name    = pwndbg.constants.syscall(syscall)
    else:
        return []

    result = []
    name = name or ''

    sym   = gdb.lookup_symbol(name)
    name  = name.replace('isoc99_', '') # __isoc99_sscanf
    name  = name.replace('@plt', '')    # getpwiod@plt

    # If we have particular `XXX_chk` function in our database, we use it.
    # Otherwise, we show args for its unchecked version.
    # We also lstrip `_` in here, as e.g. `__printf_chk` needs the underscores.
    if name not in pwndbg.functions.functions:
        name  = name.replace('_chk', '')
        name  = name.strip().lstrip('_')    # _malloc

    func = pwndbg.functions.functions.get(name, None)

    # Try to extract the data from GDB.
    # Note that this is currently broken, pending acceptance of
    # my patch: https://sourceware.org/ml/gdb-patches/2015-06/msg00268.html
    if sym and sym[0]:
        try:
            n_args_default = len(sym[0].type.fields())
        except TypeError:
            pass

    # Try to grab the data out of IDA
    if not func and target:
        typename = pwndbg.ida.GetType(target)

        if typename:
            typename += ';'

            # GetType() does not include the name.
            typename = typename.replace('(', ' function_name(', 1)

            for k, v in ida_replacements.items():
                typename = typename.replace(k, v)

            func = pwndbg.funcparser.ExtractFuncDeclFromSource(typename + ';')

    if func:
        args = func.args
        # Does func.name contain 'printf' as a substring? If so, it could be e.g. printf,
        # fprintf, snprintf or __printf_chk, which is the kind of functions we're interested
        # in here.
        #
        # There may be false positives like register_printf_specifier, but these will be
        # filtered out since they do not have a 'format' argument. If the last function
        # argument is not called 'vararg', it won't be processed either, as these may be
        # functions like vprintf that use a single va_list to access all args, thus the
        # approach used for variadic arguments would most likely not work for them.
        if 'printf' in func.name:
            format_str = None
            for i, arg in enumerate(args):
                if arg.name == 'format' and arg.type == 'char' and arg.derefcnt == 1:
                    format_str = pwndbg.strings.get(argument(i, abi))
                    break

            if format_str is not None:
                args = enhance_printf_args(args, format_str)
    else:
        args = [pwndbg.functions.Argument('int', 0, argname(i, abi)) for i in range(n_args_default)]

    for i, arg in enumerate(args):
        result.append((arg, argument(i, abi)))

    return result


def argname(n, abi=None):
    abi  = abi or pwndbg.abi.ABI.default()
    regs = abi.register_arguments

    if n < len(regs):
        return regs[n]

    return 'arg[%i]' % n


def argument(n, abi=None):
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    Works only for ABIs that use registers for arguments.
    """
    abi  = abi or pwndbg.abi.ABI.default()
    regs = abi.register_arguments

    if n < len(regs):
        return getattr(pwndbg.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.regs.sp + (n * pwndbg.arch.ptrsize)

    return int(pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, sp))


def arguments(abi=None):
    """
    Yields (arg_name, arg_value) tuples for arguments from a given ABI.
    Works only for ABIs that use registers for arguments.
    """
    abi  = abi or pwndbg.abi.ABI.default()
    regs = abi.register_arguments

    for i in range(len(regs)):
        yield argname(i, abi), argument(i, abi)


def enhance_printf_args(orig_args, format_str):
    args = orig_args.copy()

    vararg_arg = args.pop()
    if vararg_arg.name != 'vararg':
        return orig_args

    # NOTE: this table is currently not quite used
    len_modifier_table = {
        'hh': 'char',
        'll': 'long long',
        'h': 'short',
        'l': 'long',
        'j': 'intmax_t',
        'z': 'size_t',
        't': 'ptrdiff_t',
        'L': 'long double'
    }

    i = 0
    len_format_str = len(format_str)

    while i < len_format_str:
        if format_str[i] != '%':
            i += 1
            continue

        if i + 1 < len_format_str and format_str[i + 1] == '%':
            i += 2
            continue
        fmt_specifier_start = i
        i += 1

        # FIXME: should recognize '*' and accept additional int arguments
        while i < len_format_str and (format_str[i] in '-+ #0*.' or format_str[i].isdigit()):
            i += 1

        len_modifier_2 = format_str[i:i+2]

        specifier_type = None
        if len_modifier_2 in ('hh', 'll'):
            specifier_type = len_modifier_table[len_modifier_2]
            i += 2
        elif i < len_format_str:
            len_modifier_1 = format_str[i]
            if len_modifier_1 in len_modifier_table:
                specifier_type = len_modifier_table[len_modifier_1]
                i += 1

        if i >= len_format_str:
            break

        conv_specifier = format_str[i]
        i += 1
        new_arg = None
        arg_name = format_str[fmt_specifier_start:i]
        if conv_specifier in ('c', 'd', 'i'):
            new_arg = pwndbg.functions.Argument(type='int', derefcnt=0, name=arg_name)
        elif conv_specifier in ('o', 'x', 'X', 'u'):
            new_arg = pwndbg.functions.Argument(type='unsigned', derefcnt=0, name=arg_name)
        elif conv_specifier.lower() in ('f', 'e', 'a', 'g'):
            new_arg = pwndbg.functions.Argument(type='double', derefcnt=0, name=arg_name)
        elif conv_specifier in ('s',):
            new_arg = pwndbg.functions.Argument(type='char', derefcnt=1, name=arg_name)

        if new_arg:
            args.append(new_arg)

    return args

def format_args(instruction):
    result = []
    for arg, value in get(instruction):
        code   = arg.type != 'char'
        pretty = pwndbg.chain.format(value, code=code)

        # Enhance args display
        if arg.name == 'fd' and isinstance(value, int):
            path = pwndbg.file.readlink('/proc/%d/fd/%d' % (pwndbg.proc.pid, value))
            if path:
                pretty += ' (%s)' % path

        result.append('%-10s %s' % (N.argument(arg.name) + ':', pretty))
    return result
