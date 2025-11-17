"""
Provides decompiler integration by leveraging

https://github.com/mahaloz/decomp2dbg
"""

from __future__ import annotations

import os
import re
import xmlrpc
import xmlrpc.client
from dataclasses import dataclass
from typing import Any
from typing import Optional
from typing import Tuple
from typing import cast
import bisect

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.elf
import pwndbg.aglib.vmmap
import pwndbg.color.syntax_highlight
import pwndbg.lib.cache
import pwndbg.lib.pretty_print as pretty_print
from pwndbg.color import message

# Note that XML RPC cannot send 64-bit ints (it is capped at 32 bits).
# We hope that rebased integers will never be more than 32-bits. If need be,
# we may send them as strings.


@dataclass
class GlobalVariable:
    # FIXME: Currently, global variables don't acknowledge their actual size.
    name: str
    # Mapped address in the address space.
    addr: int


@dataclass
class GlobalVariables:
    # The list is sorted by addr
    vars: list[GlobalVariable]


@dataclass
class FunctionHeader:
    name: str
    # Mapped address in the address space.
    addr: int
    size: int


@dataclass
class FunctionHeaders:
    # The list is sorted by addr
    funcs: list[FunctionHeader]


@dataclass
class RegisterVariable:
    name: str
    type: str
    reg_name: str


@dataclass
class StackVariable:
    name: str
    # Could easily be a type that the debugger doesn't know about.
    # E.g. Ida's __int64 and other MSVCisms. Can also be something
    # non-obvious like "void (*)()".
    type: str
    # == One of the the following two offsets is guaranteed to be non-None
    # The decompiler plugin code regarding this is touchy, may not always be
    # valid.
    # The offset of the variable's address from the stack pointer. Positive number.
    from_sp: Optional[int]
    # The offset of the variable's address to the beginning of the stack frame
    # (which usually contains the saved return address). Positive number.
    from_frame: Optional[int]


@dataclass
class FuncVariables:
    stack_vars: list[StackVariable]
    reg_vars: list[RegisterVariable]


@dataclass
class FuncDecompilationResult:
    # The text containing the whole function decompilation.
    # Each element of the list is one line.
    # (contains the function signature and even stuff like IDA's
    # "// positive sp value has been detected, the output may be wrong!"
    # before the function signature)
    decompilation: list[str]
    # Says which line the requested address is in.
    # 0-indexed starting from the first line of the function.
    curr_line: int
    # The function name (not the signature!)
    func_name: str


class DecompilerConnection:
    """
    Allows communication with the decompiler.

    The lifecycle of this object is tied to the connection to the compiler.
    It is only constructed after a successful connection, and must not be used
    after the connection dies.

    You should expect every function here to be able to throw ConnectionRefusedError.
    """

    # I allow this object to be live even if the process isn't live because I want
    # people to be able to connect to the decompiler in their gdbinit.

    """The XML RPC server that is connected to the decompiler."""
    server: xmlrpc.client.ServerProxy

    """The (host filesystem) path of the binary loaded in the decompiler.
    It can be both an executable and a shared library."""
    binary_path: str

    """Version information about the decompiler we are connected to. See
    plugin server_template.py for the format.
    """
    versions: dict[str, str]

    """The address of the start of the binary in the live process address space.
    Has value -1 if the process is not live or if the binary is not loaded yet."""
    # I allow (process live, binary not loaded) because we may be syncing with the
    # decompilation of a shared library that hasn't loaded yet.
    _binary_base_addr: int

    def __init__(self, server: xmlrpc.client.ServerProxy):
        self.server = server

        self.binary_path = str(self.server.binary_path())
        self.versions = cast(dict[str, str], self.server.versions())
        self._binary_base_addr = -1

        self._find_binary_addr(print_failure=True)

    def _find_binary_addr(self, print_failure: bool = False) -> None:
        if inf := pwndbg.dbg.selected_inferior():
            if not inf.alive():
                return

            # Try to find the binary in the address space.
            start_addr: Optional[int] = pwndbg.aglib.vmmap.named_region_start(
                self.binary_path, exact_match=True
            )

            if start_addr is None:
                # Try harder! (likely we are remote debugging)
                start_addr = pwndbg.aglib.vmmap.named_region_start(
                    self.binary_path, exact_match=False
                )

                if start_addr is None:
                    if print_failure:
                        basename: str = os.path.basename(self.binary_path)
                        print(
                            message.notice(
                                f"The decompiled program {basename} doesn't seem to be loaded."
                                " We will keep an eye out for it."
                            )
                        )
                    return
                else:
                    self._binary_base_addr = start_addr
            else:
                self._binary_base_addr = start_addr

    def addr_to_mapped(self, rel_addr: int) -> int:
        """
        Takes an address relative to the image/file base and
        returns the actual address in the process' address
        space.

        self.binary_base_addr must be valid before calling this.
        """
        # If self.binary_base_addr is valid, so is
        # self._binary_base_addr :)
        assert self._binary_base_addr != -1
        return rel_addr + self._binary_base_addr

    def addr_to_relative(self, mapped_addr: int) -> int:
        """
        Takes an address from the live process' address space and returns
        the relative offset from the the image/file base.

        self.binary_base_addr must be valid before calling this.

        Assumes that this address is actually in the self.binary_path
        image rather than somewhere else. If you don't want to check this
        beforehand (because of performance), you at the very least need to
        check that the value returned here doesn't exceed XML-RPC int limits.
        """
        # If self.binary_base_addr is valid, so is
        # self._binary_base_addr :)
        assert self._binary_base_addr != -1
        return mapped_addr - self._binary_base_addr

    @property
    def binary_base_addr(self) -> int:
        if self._binary_base_addr == -1:
            self._find_binary_addr(print_failure=False)

        return self._binary_base_addr

    # ================
    # Decompiler interface.
    # Conforms to this file:
    # https://github.com/mahaloz/decomp2dbg/blob/77affe9ec1725e42739cf653a40ee6320452fd78/decompilers/server_template.py#L14
    # But the return values are repacked a bit for nicer usage.

    def disconnect(self) -> None:
        """
        Disconnects from the XML RPC server.

        Delete this object after running this function.
        """
        self.server.disconnect()
        self.binary_path = (
            "You are using a disconnected DecompilerConnection. This is a bug in Pwndbg."
        )
        self._binary_base_addr = -2

    def decompile(self, mapped_addr: int) -> Optional[FuncDecompilationResult]:
        """
        See IntegrationManager.decompile() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        rel_addr = self.addr_to_relative(mapped_addr)

        if rel_addr < xmlrpc.client.MININT or rel_addr > xmlrpc.client.MAXINT:
            # The user probably provided an address outside of the mappings of the
            # binary being decompiled.
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.decompile(rel_addr))

        if answer["decompilation"] is None:
            # Assuming all the other fields are as well
            return None

        return FuncDecompilationResult(
            decompilation=answer["decompilation"],
            curr_line=answer["curr_line"],
            func_name=answer["func_name"],
        )

    def function_data(self, mapped_addr: int) -> Optional[FuncVariables]:
        """
        See IntegrationManager.function_data() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        rel_addr = self.addr_to_relative(mapped_addr)

        if rel_addr < xmlrpc.client.MININT or rel_addr > xmlrpc.client.MAXINT:
            # The user probably provided an address outside of the mappings of the
            # binary being decompiled.
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.function_data(rel_addr))

        if answer["stack_vars"] is None:
            return None

        stack_vars: list[StackVariable] = []
        reg_vars: list[RegisterVariable] = []

        for svar in answer["stack_vars"]:
            name = svar["name"]
            type_ = svar["type"]
            # .get() is needed because of ghidra
            from_sp_str: Optional[str] = svar.get("from_sp")
            from_frame_str: Optional[str] = svar.get("from_frame")
            from_sp: Optional[int] = int(from_sp_str, 0) if from_sp_str is not None else None
            from_frame: Optional[int] = (
                int(from_frame_str, 0) if from_frame_str is not None else None
            )

            stack_vars.append(
                StackVariable(name=name, type=type_, from_sp=from_sp, from_frame=from_frame)
            )

        for rvar in answer["reg_vars"]:
            name = rvar["name"]
            type_ = rvar["type"]
            reg_name = rvar["reg_name"]
            reg_vars.append(RegisterVariable(name=name, type=type_, reg_name=reg_name))

        return FuncVariables(stack_vars=stack_vars, reg_vars=reg_vars)

    def function_headers(self) -> Optional[FunctionHeaders]:
        """
        See IntegrationManager.function_headers() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.function_headers())

        functions: list[FunctionHeader] = []

        for key, value in answer.items():
            name: str = value["name"]  # type: ignore  # noqa: PGH003
            size_: int = value["size"]  # type: ignore  # noqa: PGH003
            addr: int = self.addr_to_mapped(int(key, 0))
            functions.append(FunctionHeader(name=name, addr=addr, size=size_))

        functions = sorted(functions, key=lambda f: f.addr)
        return FunctionHeaders(funcs=functions)

    def global_vars(self) -> Optional[GlobalVariables]:
        """
        See IntegrationManager.global_vars() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.global_vars())

        variables: list[GlobalVariable] = []

        for key, value in answer.items():
            addr: int = self.addr_to_mapped(int(key, 0))
            name: str = value["name"]  # type: ignore  # noqa: PGH003
            variables.append(GlobalVariable(name=name, addr=addr))

        variables = sorted(variables, key=lambda v: v.addr)
        return GlobalVariables(vars=variables)

    def structs(self):
        # return self.server.structs()
        raise NotImplementedError()

    def breakpoints(self):
        # return self.server.breakpoints()
        raise NotImplementedError()

    # .binary_path and .versions are properties rather than functions

    def focus_address(self, mapped_addr: int) -> Optional[bool]:
        """
        See IntegrationManager.focus_address() for the function description.
        """

        if self.binary_base_addr == -1:
            return None

        rel_addr = self.addr_to_relative(mapped_addr)

        if rel_addr < xmlrpc.client.MININT or rel_addr > xmlrpc.client.MAXINT:
            # The user probably provided an address outside of the mappings of the
            # binary being decompiled.
            return None

        answer: bool = cast(bool, self.server.focus_address(rel_addr))
        return answer

    # ================


class IntegrationManager:
    """
    A singleton class that manages all integration-related stuff.

    We can connect to only one decompiler at a time, and acknowledge only
    one file that decompiler is decompiling.
    (Could be relaxed in the future! Especially the latter.)

    All functions except connect() and disconnect() are no-op if we aren't
    connected.
    """

    connection: Optional[DecompilerConnection]

    def __init__(self) -> None:
        self.connection = None

        # The local caches, invalidated on disconnect/reconnect or user request.
        # They MUST be None if self.connection is None.
        self._function_headers: Optional[FunctionHeaders] = None
        self._global_vars: Optional[GlobalVariables] = None

    def invalidate_caches(self) -> None:
        self._function_headers = None
        self._global_vars = None

    def connect(self, host: str, port: int) -> bool:
        """
        Connects to the remote decompiler.

        Always invalidates the previous connection. This manager
        saves the new connection internally only if it succeeds.

        Returns True if the connection succeeded, otherwise False.
        """
        # Disconnect from previous connection. We also invalidate the cache here.
        self.disconnect()

        # Create a decompiler server connection and test it
        try:
            server = xmlrpc.client.ServerProxy(f"http://{host}:{port}")
            server.ping()
            # Success!
            self.connection = DecompilerConnection(server)
            return True
        except Exception:
            pass

        # The connection could fail because its a Ghidra connection on endpoint d2d
        try:
            server = xmlrpc.client.ServerProxy(f"http://{host}:{port}").d2d
            server.ping()
            # Success!
            self.connection = DecompilerConnection(server)
            return True
        except (ConnectionRefusedError, AttributeError):
            pass

        # Failed to connect.
        return False

    def disconnect(self) -> None:
        # We don't want to keep the data from the previous session.
        # FIXME: Ideally, we should also remove-symbol-file and delete the convenience variables.
        self.invalidate_caches()

        if self.connection is not None:
            self.connection.disconnect()
            self.connection = None

    def is_connected(self) -> bool:
        return self.connection is not None

    def update_symbols(self) -> None:
        """
        Update global variables and functions in the debugger.

        FIXME: Currently they are all 8 bytes in size.
        """
        # We need to bail even if we are connected, but the binary is not loaded into
        # the address space yet.
        if self.connection is None or self.connection.binary_base_addr == -1:
            return

        global_vars: Optional[GlobalVariables] = self.global_vars()
        func_headers: Optional[FunctionHeaders] = self.function_headers()
        # (name, address)
        syms_to_add: list[Tuple[str, int]] = []
        # To get rid of duplicates
        sym_name_set: set = set()

        if func_headers is not None:
            for func in func_headers.funcs:
                syms_to_add.append((func.name, func.addr))

        if global_vars is not None:
            for var in global_vars.vars:
                clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", var.name)
                # never re-add globals with the same name as a func
                if clean_name in sym_name_set:
                    continue

                syms_to_add.append((clean_name, var.addr))

        if not syms_to_add:
            return

        path = pwndbg.aglib.elf.create_blank_elf()
        if path is None:
            return

        try:
            # path is not None means lief is installed
            import lief

            symelf = lief.ELF.parse(path)
            if symelf is None:
                return

            for sym_name, sym_addr in syms_to_add:
                symelf.add_symtab_symbol(symelf.export_symbol(sym_name, sym_addr))

            symelf.write(path)

            if inf := pwndbg.dbg.selected_inferior():
                inf.add_symbol_file(path)
                print(message.success(f"Added {len(syms_to_add)} symbols"))
        except Exception as e:
            print(message.error(e))

    def _clean_type_str(self, type_str: str) -> str:
        # FIXME:
        # 1. this is too aggressive
        # 2. if we start adding types to the debugger then it doesn't matter
        if "__" in type_str:
            type_str = type_str.replace("__", "")
            idx = type_str.find("[")
            if idx != -1:
                type_str = type_str[:idx] + "_t" + type_str[idx:]
            else:
                type_str += "_t"
        type_str = type_str.replace("unsigned ", "u")

        return type_str

    def _try_setting_conv_var_with_type(self, name: str, value: str, type: str) -> None:
        """
        Try setting a convenience variable with a type. If it fails try with void* .
        If that fails as well, thats okay, you can't win them all.
        """
        try:
            pwndbg.dbg.set_convenience_var(name, value, type)
            return
        except Exception:
            pass

        try:
            pwndbg.dbg.set_convenience_var(name, value, "void*")
        except Exception:
            pass

    def get_stack_vars_from_frame(self, frame: pwndbg.dbg_mod.Frame) -> dict[int, str]:
        """
        Ask the decompiler for stack variable offsets in this frame and resolve
        each variable to an actual address.

        Returns:
            A dictionary that maps (stack variable address) -> (stack variable name)
            for all variables in the given frame.
        """
        if self.connection is None:
            return {}

        addr = frame.pc()

        maybe_func_data: Optional[FuncVariables] = self.connection.function_data(addr)
        if maybe_func_data is None:
            return {}

        inf = pwndbg.dbg.selected_inferior()
        if not inf:
            return {}

        func_data: FuncVariables = maybe_func_data

        result: dict[int, str] = {}

        for stack_var in func_data.stack_vars:
            from_sp: Optional[int] = stack_var.from_sp
            from_frame: Optional[int] = stack_var.from_frame

            if from_sp is not None and pwndbg.aglib.regs.stack is not None:
                stack_addr = frame.regs().by_name(pwndbg.aglib.regs.stack)
                if stack_addr:
                    var_addr = int(stack_addr) + from_sp
                    result[var_addr] = stack_var.name
            elif from_frame is not None:
                if (frame_start := frame.start()) is not None:
                    var_addr = frame_start - from_frame
                    result[var_addr] = stack_var.name

        return result

    @pwndbg.lib.cache.cache_until("stop")
    def get_all_stack_variables(self) -> dict[int, str]:
        """
        Take all valid stack frames (from the whole backtrace), ask the decompiler to
        figure out where they are, and map them to their actual addresses.

        Returns:
            A dictionary that maps (stack variable address) -> (stack variable name)
            for all currently valid stack frames.
        """
        if self.connection is None:
            return {}

        thread = pwndbg.dbg.selected_thread()
        if thread is None:
            return {}

        result: dict[int, str] = {}

        with thread.bottom_frame() as bottom_frame:
            cur_frame = bottom_frame
            # Crawl up the stack
            while cur_frame is not None:
                cur_variables = self.get_stack_vars_from_frame(cur_frame)
                # Merge dictionaries
                result = result | cur_variables
                cur_frame = cur_frame.parent()

        return result

    def update_function_variables(self, addr: int) -> None:
        """
        Take the function at `addr` and update all the debugger convenience variables
        that correspond to the function's variables.

        FIXME: Currently this kinda doesn't work if it runs while we are in the function
        prologue. We should ideally run it only when we enter new functions and are past
        their prologues.
        """
        if self.connection is None:
            return

        maybe_func_data: Optional[FuncVariables] = self.connection.function_data(addr)
        if maybe_func_data is None:
            return

        func_data: FuncVariables = maybe_func_data

        for reg_var in func_data.reg_vars:
            cleaned_type: str = self._clean_type_str(reg_var.type)
            self._try_setting_conv_var_with_type(reg_var.name, f"${reg_var.reg_name}", cleaned_type)

        for stack_var in func_data.stack_vars:
            # Pointer to the type.
            cleaned_type: str = f"{self._clean_type_str(stack_var.type)}*"
            from_sp: Optional[int] = stack_var.from_sp
            from_frame: Optional[int] = stack_var.from_frame

            # We do not account for a stack going upwards. If you have that you have bigger issues.

            if from_sp is not None and pwndbg.aglib.regs.sp is not None:
                # We prefer sp-offseted variables because calculating their actual address will always work
                var_addr = pwndbg.aglib.regs.sp + from_sp
                self._try_setting_conv_var_with_type(stack_var.name, hex(var_addr), cleaned_type)
            elif from_frame is not None and (frame := pwndbg.dbg.selected_frame()) is not None:
                if (frame_start := frame.start()) is not None:
                    var_addr = frame_start - from_frame
                    self._try_setting_conv_var_with_type(
                        stack_var.name, hex(var_addr), cleaned_type
                    )

    @staticmethod
    def _pretty_decompiler_name(id_name: str) -> str:
        """
        Takes the name returned by self.connection.versions["name"], returns
        a nicer one for user output.
        """
        mapping = {"ida": "IDA", "binaryninja": "Binary Ninja", "ghidra": "Ghidra"}
        return mapping[id_name]

    def version_string(self) -> Optional[str]:
        """
        Get a string with version information about the decompiler environment.
        """
        if self.connection is None:
            return None

        versions = self.connection.versions
        if len(versions) == 0:
            # Will happen with angr
            return None

        name: str = self._pretty_decompiler_name(versions["name"])
        ver: str = versions["version"]

        res = f"{name}: {ver}"
        # Add all other auxiliary information, no matter what it is.
        for key, value in versions.items():
            if key == "name" or key == "version":
                continue
            res += f"\n{name} {key}: {value}"

        return res

    def decompile_pretty(self, mapped_addr: int, nlines: int = -1) -> Optional[list[str]]:
        """
        Get the prettified decompilation of a function.

        The following things are done:
        + syntax highlighting
        + '►' indicator at the current line
        + trimmed to only return `nlines` lines (surrounding the mapped_addr) (returns all lines if nlines == -1)

        Returns a list of strings each representing one line of the decompilation.
        """
        if self.connection is None:
            return None

        func_decomp: Optional[FuncDecompilationResult] = self.decompile_raw(mapped_addr)

        if func_decomp is None:
            return None

        # Logic similar to pwndbg.commands.context.get_filename_and_formatted_source().

        decomp: list[str] = []

        if pwndbg.config.syntax_highlight:
            highlighted = pwndbg.color.syntax_highlight.syntax_highlight(
                "\n".join(func_decomp.decompilation), f"decompiled_{func_decomp.func_name}.c"
            )
            decomp = highlighted.splitlines()
        else:
            decomp = func_decomp.decompilation

        curr_line = func_decomp.curr_line

        formatted_decomp = pretty_print.format_source(list(decomp), nlines, curr_line)
        return formatted_decomp

    def symbol_at_address(self, mapped_addr: int) -> Optional[str]:
        """
        Returns name of a symbol (function or global variable) at given address,
        or None if there is nothing there.

        FIXME: Currently, global variables don't acknowledge their actual size.
        FIXME2: After update_symbols() is updated to acknowledge symbol sizes, this will be obsolete.
        """
        if self.connection is None:
            return None

        global_vars: Optional[GlobalVariables] = self.global_vars()
        func_headers: Optional[FunctionHeaders] = self.function_headers()

        if func_headers:
            # Binary search since the array is guaranteed to be sorted.
            idx = bisect.bisect_right(func_headers.funcs, mapped_addr, key=lambda f: f.addr)
            if idx != 0:
                possible_match = func_headers.funcs[idx - 1]
                if possible_match.addr <= mapped_addr < possible_match.addr + possible_match.size:
                    return possible_match.name

        if global_vars:
            # Binary search since the array is guaranteed to be sorted.
            idx = bisect.bisect_right(global_vars.vars, mapped_addr, key=lambda v: v.addr)
            if idx != 0:
                possible_match = global_vars.vars[idx - 1]
                if possible_match.addr == mapped_addr:
                    return possible_match.name

        return None

    # == Direct passthrough to the connection ==

    def decompile_raw(self, mapped_addr: int) -> Optional[FuncDecompilationResult]:
        """
        Returns the decompilation of the function which contains address `mapped_addr`.

        Generally you should use self.decompile_pretty().
        """
        # I intentionally didn't name this function just `decompile` to prevent
        # people from accidentally using it when there is a better alternative.
        if self.connection is not None:
            return self.connection.decompile(mapped_addr)

    def function_data(self, mapped_addr: int) -> Optional[FuncVariables]:
        """
        Returns the variables of the function which contains address `mapped_addr`.

        The "offset" field of the stack variables is poorly defined.

        The register variables are quite best effort and do not actually take
        the asked for address into account. In other words, the output for these
        may be just plain wrong.

        Function arguments are included in these variables.
        """
        if self.connection is not None:
            return self.connection.function_data(mapped_addr)

    def function_headers(self) -> Optional[FunctionHeaders]:
        """
        Returns the name, address and size off all functions in the binary, sorted
        by address.
        """
        if self.connection is not None and self._function_headers is None:
            self._function_headers = self.connection.function_headers()
        return self._function_headers

    def global_vars(self) -> Optional[GlobalVariables]:
        """
        Returns the name and address of all global variables in the binary, sorted
        by address.
        """
        if self.connection is not None and self._global_vars is None:
            self._global_vars = self.connection.global_vars()
        return self._global_vars

    def structs(self):
        raise NotImplementedError()

    def breakpoints(self):
        raise NotImplementedError()

    def focus_address(self, mapped_addr: int) -> bool:
        """
        Focus (jump to) this address in the decompiler.
        """
        if self.connection is not None:
            ans = self.connection.focus_address(mapped_addr)
            return ans if ans is not None else False
        else:
            return False


manager: IntegrationManager = IntegrationManager()
