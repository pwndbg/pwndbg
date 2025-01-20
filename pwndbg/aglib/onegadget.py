from __future__ import annotations

import ctypes
import hashlib
import os
import re
import subprocess
from enum import Enum
from typing import Any
from typing import Dict
from typing import Tuple

from tabulate import tabulate

import pwndbg.aglib.arch
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.color.message as M
import pwndbg.dbg
import pwndbg.glibc
import pwndbg.lib.cache
import pwndbg.lib.tempfile
from pwndbg.color import colorize
from pwndbg.color import generateColorFunction

ADDRESS_WRITABLE_PATTERN = re.compile(r"address(?:es)? (.*) (?:is|are) writable")
WRITABLE_COLON_PATTERN = re.compile(r"writable: (.*)")
EQUAL_NULL_PATTERN = re.compile(r"(.*) == NULL")
VALID_POSIX_SPAWN_FILE_ACTIONS_PATTERN = re.compile(r"(.*) <= 0")
VALID_ARGV_PATTERN = re.compile(r"(.+) is a valid argv")
VALID_ENVP_PATTERN = re.compile(r"(.+) is a valid envp")
IS_ALIGNED_PATTERN = re.compile(r"(.+) & 0xf == (\d+)")
IS_GOT_ADDRESS_PATTERN = re.compile(r"(.+) is the GOT address of libc")
CAST_PATTERN = re.compile(r"^\([s|u]\d+\)")
XMM_SHIFT = " >> "
CONSTRAINT_SEPARATOR = " || "
CAST_DEREF_MAPPING = {
    "(u16)": pwndbg.aglib.memory.u16,
    "(s16)": pwndbg.aglib.memory.s16,
    "(u32)": pwndbg.aglib.memory.u32,
    "(s32)": pwndbg.aglib.memory.s32,
    "(u64)": pwndbg.aglib.memory.u64,
    "(s64)": pwndbg.aglib.memory.s64,
}
CAST_MAPPING = {
    "(u16)": lambda x: ctypes.c_uint16(x).value,
    "(s16)": lambda x: ctypes.c_int16(x).value,
    "(u32)": lambda x: ctypes.c_uint32(x).value,
    "(s32)": lambda x: ctypes.c_int32(x).value,
    "(u64)": lambda x: ctypes.c_uint64(x).value,
    "(s64)": lambda x: ctypes.c_int64(x).value,
}
ONEGADGET_COLOR = {
    "light_green": lambda x: colorize(x, "\x1b[38;5;82m"),
    "light_purple": lambda x: colorize(x, "\x1b[38;5;153m"),
}
ONEGADGET_CACHEDIR = pwndbg.lib.tempfile.cachedir("onegadget")


class CheckSatResult(Enum):
    SAT = 1
    UNSAT = 0
    UNKNOWN = -1

    def __str__(self) -> str:
        return self.name

    def __and__(self, other: CheckSatResult) -> CheckSatResult:
        if self == CheckSatResult.UNSAT or other == CheckSatResult.UNSAT:
            return CheckSatResult.UNSAT
        elif self == CheckSatResult.UNKNOWN or other == CheckSatResult.UNKNOWN:
            return CheckSatResult.UNKNOWN
        else:
            return CheckSatResult.SAT

    def __or__(self, other: CheckSatResult) -> CheckSatResult:
        if self == CheckSatResult.SAT or other == CheckSatResult.SAT:
            return CheckSatResult.SAT
        elif self == CheckSatResult.UNKNOWN or other == CheckSatResult.UNKNOWN:
            return CheckSatResult.UNKNOWN
        else:
            return CheckSatResult.UNSAT


SAT = CheckSatResult.SAT
UNSAT = CheckSatResult.UNSAT
UNKNOWN = CheckSatResult.UNKNOWN


class Lambda:
    """
    Modified from onegadget's Lambda class

    https://github.com/david942j/one_gadget/blob/65ce1dade70bf89e7496346ccf452ce5b2d139b3/lib/one_gadget/emulators/lambda.rb#L13
    """

    def __init__(self, obj: str | Lambda) -> None:
        self.immi = 0
        self.obj = obj
        self.deref_count = 0

    def __add__(self, other: int) -> Lambda:
        if not isinstance(other, int):
            raise ValueError(f"Expect other({other}) to be numeric.")

        if self.deref_count > 0:
            ret = Lambda(self)
        else:
            ret = Lambda(self.obj)
            ret.immi = self.immi
        ret.immi += other
        return ret

    def __sub__(self, other: int) -> Lambda:
        return self + (-other)

    def __str__(self) -> str:
        str_repr = ""
        str_repr += "[" * self.deref_count
        str_repr += str(self.obj) if self.obj is not None else ""
        str_repr += f"{self.immi:+#x}" if self.immi != 0 else ""
        str_repr += "]" * self.deref_count
        return str_repr

    def __repr__(self) -> str:
        return f"<Lambda obj={self.obj}, immi={self.immi}, deref_count={self.deref_count}>"

    @property
    def gdb_expr(self) -> str:
        # TODO: Don't use gdb.parse_and_eval here, directly fetching the value with `pwndbg.aglib.memory` would be better(?)
        obj = self.obj
        if isinstance(obj, str):
            if obj.startswith("xmm"):
                # Currently, "xmm\d >> {ptrsize*8}" only happens here:
                # https://github.com/david942j/one_gadget/blob/65ce1dade70bf89e7496346ccf452ce5b2d139b3/lib/one_gadget/emulators/x86.rb#L242-L248
                # So we can hardcode the shifting :p
                # TODO: Handle xmm register in a better way

                # TODO: In LLDB this syntax is invalid:
                # error: <user expression 62>:1:23: illegal vector component name 'v'
                #     1 | ((unsigned long)($xmm0.v2_int64[1]))
                #       |                       ^~~~~~~~~
                #  while parsing (u64)xmm0 >> 64 for argv[1]

                bits = pwndbg.aglib.arch.ptrsize * 8
                if XMM_SHIFT in obj:
                    obj = obj.replace(XMM_SHIFT + str(bits), f".v{128 // bits}_int{bits}[1]")
                else:
                    obj += f".v{128 // bits}_int{bits}[0]"
            obj = f"(unsigned long)(${obj})"
        elif isinstance(obj, Lambda):
            obj = obj.gdb_expr
        else:
            raise ValueError(f"Unsupported obj: {obj}")
        str_repr = ""
        if self.deref_count > 0:
            str_repr += f"{'*' * self.deref_count}(unsigned long{'*' * self.deref_count})"
        str_repr += "("
        str_repr += obj
        str_repr += f"{self.immi:+#x}" if self.immi != 0 else ""
        str_repr += ")"
        return str_repr

    @property
    def color_str(self) -> str:
        str_repr = ""
        str_repr += "[" * self.deref_count
        if isinstance(self.obj, Lambda):
            str_repr += str(self.obj)
        elif self.obj:
            str_repr += colorize_reg(str(self.obj))
        if self.immi != 0:
            str_repr += "-" if self.immi < 0 else "+"
            str_repr += colorize_integer(hex(abs(self.immi)))
        str_repr += "]" * self.deref_count
        return str_repr

    def deref(self) -> Lambda:
        ret = Lambda(self.obj)
        ret.immi = self.immi
        ret.deref_count = self.deref_count + 1
        return ret

    def deref_(self) -> None:
        self.deref_count += 1

    def ref(self) -> Lambda:
        if self.deref_count <= 0:
            raise ValueError("Cannot reference anymore!")
        self.deref_count -= 1
        return self

    def evaluate(self, context: Dict[Any, Any]) -> int | Lambda:
        if self.deref_count > 0 or (self.obj and self.obj not in context):
            raise ValueError(f"Can't eval {self}")
        return context[self.obj] + self.immi

    @staticmethod
    def parse(argument: str, predefined: Dict[Any, Any] = {}) -> int | Lambda:
        if not argument or argument == "!":
            return 0
        try:
            return int(argument, 0)
        except ValueError:
            pass

        # nested []
        if argument.startswith("["):
            ridx = argument.rindex("]")
            immi = Lambda.parse(argument[(ridx + 1) :])
            lm = Lambda.parse(argument[1:ridx], predefined)
            if not isinstance(lm, Lambda) or not isinstance(immi, int):
                raise ValueError(f"Unsupported instruction argument: {argument}")
            lm = lm.deref()
            if immi:
                lm += immi
            return lm

        base, disp = Lambda.mem_obj(argument)
        obj = predefined.get(base, Lambda(base))
        if disp:
            obj += disp
        return obj

    @staticmethod
    def mem_obj(arg: str) -> Tuple[str, int]:
        tokens = re.split(r"[+\-]", arg)
        if len(tokens) == 1:
            return tokens[0], 0
        if len(tokens) == 2:
            return tokens[0], int(tokens[1], 0) * (-1 if "-" in arg else 1)
        raise ValueError(f"Unsupported instruction argument: {arg}")


def colorize_reg(x: object) -> str:
    return generateColorFunction("light_green", ONEGADGET_COLOR)(x)


def colorize_integer(x: object) -> str:
    return generateColorFunction("light_purple", ONEGADGET_COLOR)(x)


def colorize_psuedo_code(code: str) -> str:
    """
    Colorize the pseudo code of onegadget
    """
    args_start = code.find("(")
    output = code[:args_start]
    args = []
    for arg in code[args_start + 1 : -1].split(", "):
        if arg[0] != '"' and arg != "environ":
            lambda_expr = Lambda.parse(arg)
            if isinstance(lambda_expr, Lambda):
                args.append(lambda_expr.color_str)
            else:
                args.append(colorize_integer(lambda_expr))
        else:
            args.append(arg)
    output += "(" + ", ".join(args) + ")"
    return output


def compute_file_hash(filename: str) -> str:
    """
    Compute the MD5 hash of the file, return the hash
    """
    h = hashlib.md5()
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


@pwndbg.lib.cache.cache_until("start", "objfile")
def run_onegadget() -> str:
    """
    Run onegadget and return the output
    """
    libc_path = pwndbg.aglib.file.get_file(pwndbg.glibc.get_libc_filename_from_info_sharedlibrary())
    # We need cache because onegadget might be slow
    cache_file = os.path.join(ONEGADGET_CACHEDIR, compute_file_hash(libc_path))
    if os.path.exists(cache_file):
        # Cache hit
        with open(cache_file) as f:
            return f.read()
    # Cache miss
    output = subprocess.check_output(["one_gadget", "--level=100", libc_path], text=True)
    with open(cache_file, "w") as f:
        f.write(output)
    return output


def parse_expression(expr: str) -> Tuple[int | None, str, str | None]:
    """
    Parse expression, return the result, colorized string and error message
    """
    # Remove cast
    match = CAST_PATTERN.match(expr)
    cast = match.group(0) if match else ""
    if cast:
        expr = expr[len(cast) :]
    if expr.startswith("("):
        # Remove the first and last parenthesis
        expr = expr[1:-1]
    lambda_expr = Lambda.parse(expr)
    if not isinstance(lambda_expr, Lambda):
        return lambda_expr, expr, None

    gdb_expr = lambda_expr.gdb_expr
    try:
        if cast:
            if gdb_expr.startswith("*"):
                # Remove the first *, we use cast to handle it instead of unsigned long
                gdb_expr = gdb_expr.lstrip("*")
                # Now gdb_expr is a pointer, we need dereference it with cast
                addr = int(pwndbg.dbg.selected_inferior().evaluate_expression(gdb_expr))
                result = CAST_DEREF_MAPPING[cast](addr)
            else:
                addr = int(pwndbg.dbg.selected_inferior().evaluate_expression(gdb_expr))
                result = CAST_MAPPING[cast](addr)
        else:
            addr = int(pwndbg.dbg.selected_inferior().evaluate_expression(gdb_expr))
            result = addr

        return result, f"{cast}{lambda_expr.color_str}", None
    except pwndbg.dbg_mod.Error as e:
        return None, f"{cast}{lambda_expr.color_str}", str(e)


def check_stack_argv(expr: str) -> Tuple[CheckSatResult, str]:
    """
    Check argv that's on the stack, return the result and the message
    """
    output_msg = ""
    exprs = expr[1:-1].split(", ")

    n = 0
    for expr in exprs:
        if "sh" in expr or "-c" in expr:
            output_msg += f"argv[{n}] = {expr}\n"
            n += 1
            continue

        if expr == "NULL":
            output_msg += f"argv[{n}] = {expr}\n"
            return UNKNOWN, output_msg

        if expr == "...":
            output_msg += f"argv doesn't end, please check argv[{n}..n] manually\n"
            return UNKNOWN, output_msg

        result, color_str, err = parse_expression(expr)
        if err is not None:
            output_msg += f"{err} while parsing {color_str} for argv[{n}]\n"
            return UNSAT, output_msg
        if result == 0:
            if n > 1 and "-c" in exprs[n - 1]:
                output_msg += f'argv[{n}] = {color_str} = NULL, {color_str} can\'t be NULL because argv[{n-1}] = "-c"\n'
                return UNSAT, output_msg
            else:
                output_msg += f"argv[{n}] = {color_str} = NULL\n"
            if n > 1:
                return UNKNOWN, output_msg
            return SAT, output_msg
        page = pwndbg.aglib.vmmap.find(result)
        if page is None or not page.read:
            output_msg += (
                f"argv[{n}] = {color_str} = {result:#x}, {color_str} is not a valid address\n"
            )
            return UNSAT, output_msg
        if n > 0:
            output_msg += f"argv[{n}] = {color_str} = {result:#x} -> {bytes(pwndbg.aglib.memory.string(result))!r}\n"
        else:
            output_msg += (
                f"argv[{n}] = {color_str} = {result:#x}, {color_str} is a readable address\n"
            )
        n += 1

    return SAT, output_msg


def check_non_stack_argv(expr: str) -> Tuple[CheckSatResult, str]:
    """
    Check argv that's not on the stack, return the result and the message
    """
    output_msg = ""
    argv, color_str, err = parse_expression(expr)
    if err is not None:
        # We don't have to print the error message here, it should be printed already
        return UNSAT, f"{err} while parsing {color_str}\n"

    output_msg += f"Assume argv = {color_str} = {argv:#x}, checking the content of argv\n"

    n = 0
    while True:
        try:
            argv_n = pwndbg.aglib.memory.pvoid(argv + n * pwndbg.aglib.arch.ptrsize)
        except pwndbg.dbg_mod.Error:
            output_msg += f"&argv[{n}] = {argv + n * pwndbg.aglib.arch.ptrsize:#x}, {argv + n * pwndbg.aglib.arch.ptrsize:#x} is a invalid address\n"
            return UNSAT, output_msg
        if argv_n == 0:
            if n > 1:
                output_msg += f"argv[{n}] is NULL, {color_str} might be a valid argv\n"
                return UNKNOWN, output_msg
            else:
                # {whatever_but_readable, NULL} is always a valid argv
                output_msg += f"argv[{n}] is NULL, {color_str} is a valid argv\n"
            return SAT, output_msg
        page = pwndbg.aglib.vmmap.find(argv_n)
        if page is None or not page.read:
            output_msg += f"argv[{n}] = {argv_n:#x}, {argv_n:#x} is a invalid address\n"
            return UNSAT, output_msg
        output_msg += f"argv[{n}] = {argv_n:#x} -> {bytes(pwndbg.aglib.memory.string(argv_n))!r}\n"
        n += 1


def check_argv(expr: str) -> Tuple[CheckSatResult, str]:
    """
    Check argv, return the result and the message
    """
    if expr.startswith("{"):
        return check_stack_argv(expr)
    return check_non_stack_argv(expr)


def check_envp(expr: str) -> Tuple[bool, str]:
    """
    Check envp, return the result and the message
    """
    output_msg = ""
    if expr.startswith("{"):
        # Note: we don't have to handle this case for now, but might need to implement it in the future
        return False, output_msg

    envp, color_str, err = parse_expression(expr)
    if err is not None:
        # we don't have to print the error message here, it should be printed already
        return False, f"{err} while parsing {color_str}\n"

    output_msg += f"Assume envp = {color_str} = {envp:#x}, checking the content of envp\n"

    # we need to make sure envp[0] is a valid pointer
    # until envp[n] is NULL
    n = 0
    while True:
        try:
            envp_n = pwndbg.aglib.memory.pvoid(envp + n * pwndbg.aglib.arch.ptrsize)
        except pwndbg.dbg_mod.Error:
            output_msg += f"&envp[{n}] = {envp + n * pwndbg.aglib.arch.ptrsize:#x}, {envp + n * pwndbg.aglib.arch.ptrsize:#x} is a invalid address\n"
            return False, output_msg
        if envp_n == 0:
            output_msg += f"envp[{n}] is NULL, {color_str} is a valid envp\n"
            return True, output_msg
        page = pwndbg.aglib.vmmap.find(envp_n)
        if page is None or not page.read:
            output_msg += f"envp[{n}] = {envp_n:#x}, {envp_n:#x} is a invalid address\n"
            return False, output_msg
        output_msg += f"envp[{n}] = {envp_n:#x}, {envp_n:#x} is a readable address\n"
        n += 1


def check_constraint(constraint: str) -> Tuple[CheckSatResult, str]:
    """
    Parse constraint, return the result and the message
    """
    output_msg = ""
    if CONSTRAINT_SEPARATOR in constraint:
        final_result = UNSAT
        for sub_constraint in constraint.split(CONSTRAINT_SEPARATOR):
            result, msg = check_constraint(sub_constraint)
            output_msg += msg
            final_result = final_result | result
            if final_result == SAT:
                return SAT, output_msg
        return final_result, output_msg

    passed = False

    # https://github.com/david942j/one_gadget/blob/65ce1dade70bf89e7496346ccf452ce5b2d139b3/lib/one_gadget/gadget.rb#L63-L88
    if EQUAL_NULL_PATTERN.match(constraint):
        expr = EQUAL_NULL_PATTERN.match(constraint).group(1)
        result, color_str, err = parse_expression(expr)
        if err is None:
            passed = result == 0
            output_msg += (
                f"{color_str} = {result:#x}, {color_str} {'==' if passed else '!='} NULL\n"
            )
        else:
            output_msg += f"{err} while parsing {color_str}\n"
    elif ADDRESS_WRITABLE_PATTERN.match(constraint):
        exprs = ADDRESS_WRITABLE_PATTERN.match(constraint).group(1)
        for expr in exprs.split(", "):
            result, color_str, err = parse_expression(expr)
            if err is None:
                page = pwndbg.aglib.vmmap.find(result)
                passed = page is not None and page.write
                output_msg += f"{color_str} = {result:#x}, {color_str} is {'' if passed else 'not '}writable\n"
            else:
                output_msg += f"{err} while parsing {color_str}\n"
                passed = False
            if not passed:
                break
    elif WRITABLE_COLON_PATTERN.match(constraint):
        expr = WRITABLE_COLON_PATTERN.match(constraint).group(1)
        result, color_str, err = parse_expression(expr)
        if err is None:
            page = pwndbg.aglib.vmmap.find(result)
            passed = page is not None and page.write
            output_msg += (
                f"{color_str} = {result:#x}, {color_str} is {'' if passed else 'not '}writable\n"
            )
        else:
            output_msg += f"{err} while parsing {color_str}\n"
    elif VALID_ARGV_PATTERN.match(constraint):
        arr = VALID_ARGV_PATTERN.match(constraint).group(1)
        passed, msg = check_argv(arr)
        output_msg += msg
    elif VALID_ENVP_PATTERN.match(constraint):
        expr = VALID_ENVP_PATTERN.match(constraint).group(1)
        passed, msg = check_envp(expr)
        output_msg += msg
    elif VALID_POSIX_SPAWN_FILE_ACTIONS_PATTERN.match(constraint):
        expr = VALID_POSIX_SPAWN_FILE_ACTIONS_PATTERN.match(constraint).group(1)
        result, color_str, err = parse_expression(expr)
        if err is None:
            assert isinstance(result, int)  # somehow mypy is complaining without this :/
            passed = result <= 0
            output_msg += f"{color_str} = {result:#x}, {color_str} {'<=' if passed else '>'} 0\n"
        else:
            output_msg += f"{err} while parsing {color_str}\n"
    elif IS_ALIGNED_PATTERN.match(constraint):
        expr, value = IS_ALIGNED_PATTERN.match(constraint).groups()
        value = int(value, 0)
        result, color_str, err = parse_expression(expr)
        if err is None:
            assert isinstance(result, int)  # somehow mypy is complaining without this :/
            passed = result & 0xF == value
            output_msg += f"{color_str} = {result:#x}, {color_str} & 0xf {'==' if passed else '!='} {value:#x}\n"
        else:
            output_msg += f"{err} while parsing {color_str}\n"
    elif IS_GOT_ADDRESS_PATTERN.match(constraint):
        expr = IS_GOT_ADDRESS_PATTERN.match(constraint).group(1)
        result, color_str, err = parse_expression(expr)
        if err is None:
            got_plt_address = pwndbg.glibc.get_section_address_by_name(".got.plt")
            passed = result == got_plt_address
            output_msg += f"{color_str} = {result:#x}, {color_str} is {'' if passed else 'not '}the GOT address ({got_plt_address:#x}) of libc\n"
        else:
            output_msg += f"{err} while parsing {color_str}\n"
    else:
        raise ValueError(f"Unsupported constraint: {constraint}")

    return CheckSatResult(passed), output_msg


def check_gadget(
    gadget: str, show_unsat: bool = False, no_unknown: bool = False, verbose: bool = False
) -> CheckSatResult:
    """
    Check status of each gadget, return the gadget's status
    """
    lines = gadget.splitlines()
    # First line is offset of the gadget and C pseudo code
    offset, pseudo_code = lines[0].split(maxsplit=1)
    offset = int(offset, 16)
    output_msg = colorize_integer(hex(offset)) + " " + colorize_psuedo_code(pseudo_code) + "\n"
    verbose_msg = ""
    # From third line, there're the constraints
    is_valid_gadget = SAT
    result_list = []
    for line in lines[2:]:
        line = line.strip()
        result, msg = check_constraint(line)
        is_valid_gadget = is_valid_gadget & result
        if result == SAT:
            if verbose:
                verbose_msg += msg + M.success(f"SAT: {line}") + "\n"
            result_list.append((M.success(result), M.success(line)))
        elif result == UNSAT:
            if verbose:
                verbose_msg += msg + M.error(f"UNSAT: {line}") + "\n"
            result_list.append((M.error(result), M.error(line)))
        else:
            if verbose:
                verbose_msg += msg + M.warn(f"UNKNOWN: {line}") + "\n"
            result_list.append((M.warn(result), M.warn(line)))

    if verbose:
        output_msg += verbose_msg
    output_msg += tabulate(result_list, headers=["Result", "Constraint"], tablefmt="grid") + "\n"

    if is_valid_gadget == SAT:
        print(output_msg)
    elif is_valid_gadget == UNSAT and show_unsat:
        print(output_msg)
    elif is_valid_gadget == UNKNOWN and not no_unknown:
        print(output_msg)

    return is_valid_gadget


def find_gadgets(
    show_unsat: bool = False, no_unknown: bool = False, verbose: bool = False
) -> Dict[CheckSatResult, int]:
    """
    Find gadgets by parsing the output of onegadget, return there's any valid gadget
    """
    gadgets = run_onegadget().split("\n\n")
    gadgets_count = {SAT: 0, UNSAT: 0, UNKNOWN: 0}
    for gadget in gadgets:
        result = check_gadget(gadget, show_unsat=show_unsat, no_unknown=no_unknown, verbose=verbose)
        gadgets_count[result] += 1

    return gadgets_count
