"""
Provides decompiler integration by leveraging

https://github.com/mahaloz/decomp2dbg
"""

import os
from pygments import highlight
from pygments.formatters import Terminal256Formatter
from pygments.lexers import CppLexer
import pwndbg.color.context
import pwndbg.lib.pretty_print as pretty_print
from typing import Optional
from typing import Tuple
import re
import pwndbg
from pwndbg.color import message
import pwndbg.aglib
import pwndbg.aglib.vmmap
import xmlrpc
from dataclasses import dataclass
import xmlrpc.client
from typing import Any, cast
import pwndbg.aglib.elf


# Note that XML RPC cannot send 64-bit ints (it is capped at 32 bits).
# We hope that rebased integers will never be more than 32-bits. If need be,
# we may send them as strings.


@dataclass
class GlobalVariable:
    name: str
    addr: int


@dataclass
class GlobalVariables:
    # The list is sorted by addr
    vars: list[GlobalVariable]


@dataclass
class FunctionHeader:
    name: str
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
        # The documentation for this thing in server_template.py is just completely off.
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
            addr: int = int(key, 0)
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
            addr: int = int(key, 0)
            name: str = value["name"]  # type: ignore  # noqa: PGH003
            variables.append(GlobalVariable(name=name, addr=addr))

        variables = sorted(variables, key=lambda v: v.addr)
        return GlobalVariables(vars=variables)

    # .binary_path and .versions are properties rather than functions

    def structs(self):
        # return self.server.structs()
        raise NotImplementedError()

    def breakpoints(self):
        # return self.server.breakpoints()
        raise NotImplementedError()

    # ================

# For highlighting the decompilation
_lexer = CppLexer()
_formatter = Terminal256Formatter(style="monokai")


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

    def connect(self, host: str, port: int) -> bool:
        """
        Connects to the remote decompiler.

        Always invalidates the previous connection. This manager
        saves the new connection internally only if it succeeds.

        Returns True if the connection succeeded, otherwise False.
        """

        # Disconnect from previous connection
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
        if self.connection is not None:
            self.connection.disconnect()
            self.connection = None

    def is_connected(self) -> bool:
        return self.connection is not None

    def update_symbols(self) -> None:
        """
        Update global variables and functions in the debugger.
        """
        if self.connection is None:
            return

        global_vars: Optional[GlobalVariables] = self.connection.global_vars()
        func_headers: Optional[FunctionHeaders] = self.connection.function_headers()
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

    def _try_setting_conv_var_with_type(
        self, name: str, value: str, type: str, inf: pwndbg.dbg_mod.Process
    ) -> None:
        """
        Try setting a convenience variable with a type. If it fails try with void* . If that fails as well thats okay.
        """
        try:
            inf.set_convenience_var(name, value, type)
            return
        except Exception:
            pass

        try:
            inf.set_convenience_var(name, value, "void*")
        except Exception:
            pass

    def update_function_variables(self, addr: int) -> None:
        """
        Take the function at `addr` and update all the debugger convenience variables
        that correspond to the function's variables.
        """
        if self.connection is None:
            return

        maybe_func_data: Optional[FuncVariables] = self.connection.function_data(addr)
        if maybe_func_data is None:
            return

        inf = pwndbg.dbg.selected_inferior()
        if not inf:
            return

        func_data: FuncVariables = maybe_func_data

        for reg_var in func_data.reg_vars:
            cleaned_type: str = self._clean_type_str(reg_var.type)
            self._try_setting_conv_var_with_type(
                reg_var.name, f"${reg_var.reg_name}", cleaned_type, inf
            )

        for stack_var in func_data.stack_vars:
            # Pointer to the type.
            cleaned_type: str = f"{self._clean_type_str(stack_var.type)}*"
            from_sp: Optional[int] = stack_var.from_sp
            from_frame: Optional[int] = stack_var.from_frame

            # We do not account for a stack going upwards. If you have that you have bigger issues.

            if from_sp is not None and pwndbg.aglib.regs.sp is not None:
                # We prefer sp-offseted variables because calculating their actual address will always work
                var_addr = pwndbg.aglib.regs.sp + from_sp
                self._try_setting_conv_var_with_type(
                    stack_var.name, hex(var_addr), cleaned_type, inf
                )
            elif from_frame is not None and (frame := pwndbg.dbg.selected_frame()) is not None:
                if (frame_start := frame.start()) is not None:
                    var_addr = frame_start - from_frame
                    self._try_setting_conv_var_with_type(
                        stack_var.name, hex(var_addr), cleaned_type, inf
                    )

    @staticmethod
    def _pretty_decompiler_name(id_name: str) -> str:
        """
        Takes the name returned by self.connection.versions["name"], returns
        a nicer one for user output.
        """
        mapping = {"ida": "Ida", "binaryninja": "Binary Ninja", "ghidra": "Ghidra"}
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

        func_decomp: Optional[FuncDecompilationResult] = self.decompile(mapped_addr)

        if func_decomp is None:
            return None

        # This function is similar to pwndbg.commands.context.get_filename_and_formatted_source(),
        # we should refactor a bit to use that.

        decomp: list[str] = []
        curr_line = func_decomp.curr_line


        if not pwndbg.config.disable_colors and pwndbg.config.highlight_source:
            decomp = highlight("\n".join(func_decomp.decompilation), _lexer, _formatter).splitlines()
        else:
            decomp = func_decomp.decompilation

        # Add the current line prefix
        prefix_sign = pwndbg.color.context.prefix(str(pwndbg.config.code_prefix))
        # Need to take care not to mess up the ANSI control chars
        pure_curr_line = func_decomp.decompilation[curr_line]
        if not pure_curr_line:
            decomp[curr_line] = prefix_sign + decomp[curr_line]
        else:
            # This is most likely whitespace
            first_normal = pure_curr_line[0]
            barrier = decomp[curr_line].index(first_normal)
            decomp[curr_line] = decomp[curr_line][0:barrier] + prefix_sign + decomp[curr_line][(barrier+1):]

        if nlines == -1:
            return decomp

        start, end = pretty_print.nlines_to_range(nlines, func_decomp.curr_line, len(decomp))
        return decomp[start:end]

    # == Direct passthrough to the connection ==

    def decompile(self, mapped_addr: int) -> Optional[FuncDecompilationResult]:
        """
        Returns the decompilation of the function which contains address `mapped_addr`.

        Generally you should use self.decompile_pretty().
        """
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
        if self.connection is not None:
            return self.connection.function_headers()

    def global_vars(self) -> Optional[GlobalVariables]:
        """
        Returns the name and address of all global variables in the binary, sorted
        by address.
        """
        if self.connection is not None:
            return self.connection.global_vars()

    def structs(self):
        raise NotImplementedError()

    def breakpoints(self):
        raise NotImplementedError()


manager: IntegrationManager = IntegrationManager()
