"""
Provides decompiler integration by leveraging

https://github.com/mahaloz/decomp2dbg
"""

import os
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
import pwndbg.commands
import pwndbg.commands.cymbol


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
    # Offset to the frame pointer.
    # If the function doesn't have a frame or the architecture doesn't
    # have a well defined frame pointer, this field can contain whatever.
    offset: int

@dataclass
class FuncVariables:
    stack_vars: list[StackVariable]
    reg_vars: list[RegisterVariable]

@dataclass
class FuncDecompilationResult:
    # The string containing the whole function decompilation.
    # (contains the function signature and even stuff like IDA's
    # "// positive sp value has been detected, the output may be wrong!"
    # before the function signature)
    decompilation: str
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

    """The address of the start of the binary in the live process address space.
    Has value -1 if the process is not live or if the binary is not loaded yet."""
    # I allow (process live, binary not loaded) because we may be syncing with the
    # decompilation of a shared library that hasn't loaded yet.
    _binary_base_addr: int

    def __init__(self, server: xmlrpc.client.ServerProxy):
        self.server = server

        self.binary_path = str(self.server.binary_path())
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
        Returns the decompilation of the function which contains address `mapped_addr`.
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
        Returns the variables of the function which contains address `mapped_addr`.

        The "offset" field of the stack variables is poorly defined.

        The register variables are quite best effort and do not actually take
        the asked for address into account. In other words, the output for these
        may be just plain wrong.

        Function arguments are included in these variables.
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

        for key, value in answer["stack_vars"]:
            offset = int(key, 0)
            name = value["name"]
            type_ = value["type"]
            stack_vars.append(StackVariable(name=name, type=type_, offset=offset))

        for key, value in answer["reg_vars"]:
            name = key
            reg_name = value["reg_name"]
            type_ = value["type"]
            reg_vars.append(RegisterVariable(name=name, type=type_, reg_name=reg_name))

        return FuncVariables(stack_vars=stack_vars, reg_vars=reg_vars)

    def function_headers(self) -> Optional[FunctionHeaders]:
        """
        Returns the name, address and size off all functions in the binary, sorted
        by address.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.function_headers())

        functions: list[FunctionHeader] = []

        for key, value in answer:
            name: str = value["name"]  # type: ignore  # noqa: PGH003
            size_: int = value["size"] # type: ignore  # noqa: PGH003
            addr: int = int(key, 0)
            functions.append(FunctionHeader(name=name, addr=addr, size=size_))

        functions = sorted(functions, key=lambda f: f.addr)
        return FunctionHeaders(funcs=functions)

    def global_vars(self) -> Optional[GlobalVariables]:
        """
        Returns the name and address of all global variables in the binary, sorted
        by address.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.global_vars())

        variables: list[GlobalVariable] = []

        for key, value in answer:
            addr: int = int(key, 0)
            name: str = value["name"] # type: ignore  # noqa: PGH003
            variables.append(GlobalVariable(name=name, addr=addr))

        variables = sorted(variables, key=lambda v: v.addr)
        return GlobalVariables(vars=variables)

    def structs(self):
        # return self.server.structs()
        raise NotImplementedError()

    def breakpoints(self):
        # return self.server.breakpoints()
        raise NotImplementedError()

    # ================


class IntegrationManager:
    """
    A singleton class that manages all integration-related stuff.

    We can connect to only one decompiler at a time, and acknowledge only
    one file that decompiler is decompiling.
    (Could be relaxed in the future! Especially the latter.)
    """

    def connect(self, host: str, port: int) -> Optional[DecompilerConnection]:
        """
        Connects to the remote decompiler. Returns None if the connection fails.
        """

        # Create a decompiler server connection and test it
        try:
            server = xmlrpc.client.ServerProxy(f"http://{host}:{port}")
            server.ping()
            # Success!
            return DecompilerConnection(server)
        except Exception:
            pass

        # The connection could fail because its a Ghidra connection on endpoint d2d
        try:
            server = xmlrpc.client.ServerProxy(f"http://{host}:{port}").d2d
            server.ping()
            # Success!
            return DecompilerConnection(server)
        except (ConnectionRefusedError, AttributeError):
            pass

        # Failed to connect.
        return None

    def update_symbols(self, connection: DecompilerConnection) -> None:
        """
        Update global variables and functions in the debugger.
        """

        global_vars: Optional[GlobalVariables] = connection.global_vars()
        func_headers: Optional[FunctionHeaders] = connection.function_headers()
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

        path = pwndbg.commands.cymbol.create_blank_elf()
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


manager: IntegrationManager = IntegrationManager()
