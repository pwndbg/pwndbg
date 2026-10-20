"""
Provides decompiler integration by leveraging decomp2dbg
(https://github.com/mahaloz/decomp2dbg).

Communicates with the decomp2dbg decompiler plugins by
following the API laid out in https://github.com/mahaloz/decomp2dbg/blob/main/decompilers/server_template.py.

Code used as reference:
+ https://github.com/mahaloz/decomp2dbg/blob/main/decomp2dbg/clients/client.py
+ https://github.com/mahaloz/decomp2dbg/blob/main/decomp2dbg/clients/gdb/gdb_client.py
"""

from __future__ import annotations

import bisect
import os
import re
import tempfile
import xmlrpc
import xmlrpc.client
from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import cast

import niche_elf

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.vmmap
import pwndbg.color.syntax_highlight
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.lib import pretty_print

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
    from_sp: int | None
    # The offset of the variable's address to the beginning of the stack frame
    # (which usually contains the saved return address). Positive number.
    from_frame: int | None


@dataclass
class RebasedStackVariable:
    name: str
    type: str
    # Actual valid address in the address space.
    addr: int


@dataclass
class FuncVariables:
    stack_vars: list[StackVariable]
    reg_vars: list[RegisterVariable]


@dataclass
class RebasedFuncVariables:
    stack_vars: list[RebasedStackVariable]
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


class DecompilerID(Enum):
    IDA = "IDA"
    BINARYNINJA = "Binary Ninja"
    GHIDRA = "Ghidra"
    ANGR = "angr"


_api_name_to_id = {
    "ida": DecompilerID.IDA,
    "binaryninja": DecompilerID.BINARYNINJA,
    "ghidra": DecompilerID.GHIDRA,
    "angr": DecompilerID.ANGR,
}


class Error(Enum):
    OK = "Ok."
    NO_CONNECTION = "Not connected to a decompiler"
    BINARY_NOT_LOADED = "Couldn't find binary in address space"
    DEBUGGER_NOT_SUPPORTED = "The debugger does not support this operation"
    NOT_ALIVE = "The process is not alive"
    NO_FRAME = "No stack frame found."


# If the user wants to override our automatic detection
manual_binary_address: int = -1
manual_binary_path: str = ""


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

    """The (host filesystem) path of the binary loaded as reported by the decompiler.
    It can be both an executable and a shared library.
    May not be relevant if manual_binary_address or manual_binary_path are set."""
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
        if manual_binary_address != -1:
            # The user hardcoded the binary base address via `di setbase`.
            self._binary_base_addr = manual_binary_address
            return

        try:
            inf = pwndbg.dbg.selected_inferior()
        except pwndbg.dbg_mod.NoInferior:
            return

        if not inf.alive():
            return

        if manual_binary_path != "":
            # The user overrode what the decompiler says via `di setpath`.
            path: str = manual_binary_path
        else:
            path = self.binary_path

        # Try to find the binary in the address space.
        start_addr: int | None = pwndbg.aglib.vmmap.named_region_start(path, exact_match=True)

        if start_addr is None:
            # Try harder! (likely we are remote debugging)
            start_addr = pwndbg.aglib.vmmap.named_region_start(path, exact_match=False)

            if start_addr is None:
                if print_failure:
                    basename: str = os.path.basename(self.binary_path)
                    print(
                        message.notice(
                            f'The decompiled program "{basename}" doesn\'t seem to be loaded.'
                            " We will keep an eye out for it.\n"
                        )
                        + "If you know that it is actually loaded, check out "
                        + message.hint("`di setpath --help`")
                        + " or "
                        + message.hint("`di setbase --help`")
                        + ".\n"
                    )
                return
            self._binary_base_addr = start_addr
        else:
            self._binary_base_addr = start_addr

        print(f"Decompiled program found @ {start_addr:#x} ({path}).")

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
        # XML RPC is stateless, there is no "disconnect"
        self.binary_path = (
            "You are using a disconnected DecompilerConnection. This is a bug in Pwndbg."
        )
        self._binary_base_addr = -2

    def decompile(self, mapped_addr: int) -> FuncDecompilationResult | None:
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

        if answer["decompilation"] is None or answer["decompilation"] == "":
            # Assuming all the other fields are as well
            return None

        return FuncDecompilationResult(
            decompilation=answer["decompilation"],
            curr_line=answer["curr_line"],
            func_name=answer["func_name"],
        )

    def function_data(self, mapped_addr: int) -> FuncVariables | None:
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
            from_sp_str: str | None = svar.get("from_sp")
            from_frame_str: str | None = svar.get("from_frame")
            from_sp: int | None = int(from_sp_str, 0) if from_sp_str is not None else None
            from_frame: int | None = int(from_frame_str, 0) if from_frame_str is not None else None

            stack_vars.append(
                StackVariable(name=name, type=type_, from_sp=from_sp, from_frame=from_frame)
            )

        for rvar in answer["reg_vars"]:
            name = rvar["name"]
            type_ = rvar["type"]
            reg_name = rvar["reg_name"]
            reg_vars.append(RegisterVariable(name=name, type=type_, reg_name=reg_name))

        return FuncVariables(stack_vars=stack_vars, reg_vars=reg_vars)

    def function_headers(self) -> FunctionHeaders | None:
        """
        See IntegrationManager.function_headers() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.function_headers())

        functions: list[FunctionHeader] = []

        for key, value in answer.items():
            name: str = value["name"]
            size_: int = value["size"]
            addr: int = self.addr_to_mapped(int(key, 0))
            functions.append(FunctionHeader(name=name, addr=addr, size=size_))

        functions = sorted(functions, key=lambda f: f.addr)
        return FunctionHeaders(funcs=functions)

    def global_vars(self) -> GlobalVariables | None:
        """
        See IntegrationManager.global_vars() for the function description.
        """
        if self.binary_base_addr == -1:
            return None

        answer: dict[str, Any] = cast(dict[str, Any], self.server.global_vars())

        variables: list[GlobalVariable] = []

        for key, value in answer.items():
            addr: int = self.addr_to_mapped(int(key, 0))
            name: str = value["name"]
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

    def focus_address(self, mapped_addr: int) -> bool | None:
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

    def __init__(self) -> None:
        # Our connection to the decompiler.
        self._connection: DecompilerConnection | None = None

        # The local caches, invalidated on disconnect/reconnect or user request.
        # They MUST return None if self.connection is None.
        self._function_headers: FunctionHeaders | None = None
        self._global_vars: GlobalVariables | None = None
        self._decompiler_id: DecompilerID | None = None
        self._function_data: dict[int, FuncVariables | None] = {}

        # FIXME: Should really be fixed on decompiler plugin side.
        # Need to maintain this, otherwise the Ghidra decompilation pane is
        # useless. https://github.com/mahaloz/decomp2dbg/issues/131
        # It's fine if this isn't cleared on manager cache invalidation methinks.
        self.__func_curr_line: dict[str, int] = {}

        # Need to maintain so we can remove-symbol-file
        self._latest_symbol_file_path: str = ""

    def invalidate_caches(self) -> None:
        self._function_headers = None
        self._global_vars = None
        self._decompiler_id = None
        self._function_data.clear()

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
            self._connection = DecompilerConnection(server)
            return True
        except xmlrpc.client.Fault:
            # It's possible that Ghidra is on the other side.
            pass
        except ConnectionRefusedError:
            # The server probably just isn't running
            pass

        # The connection could have failed because it's a Ghidra connection on endpoint d2d
        try:
            server = xmlrpc.client.ServerProxy(f"http://{host}:{port}").d2d
            server.ping()
            # Success!
            self._connection = DecompilerConnection(server)
            return True
        except (ConnectionRefusedError, AttributeError):
            # We could also silently catch xmlrpc.client.Fault
            # but those are usually genuine bugs, so we kinda want to know about them.
            pass

        # Failed to connect.
        return False

    def remove_symbols(self, inf: pwndbg.dbg_mod.Process | None = None) -> bool:
        """
        Remove the decompiler symbols that we added latest.

        Returns whether we suceeded. Resets self._latest_symbol_file_path regardless
        of success.

        FIXME: Only works for GDB :(
        """
        path: str = self._latest_symbol_file_path
        self._latest_symbol_file_path = ""

        if not path:
            return False

        try:
            if inf is None:
                inf = pwndbg.dbg.selected_inferior()
            # FIXME: Only implemented in GDB :(
            if pwndbg.dbg.name() == pwndbg.dbg_mod.DebuggerType.GDB:
                return inf.remove_symbol_file(path)
        except pwndbg.dbg_mod.NoInferior:
            pass

        return False

    def disconnect(self) -> None:
        # We don't want to keep the data from the previous session.
        # FIXME: Ideally, we should also delete the convenience variables.
        self.remove_symbols()

        self.invalidate_caches()

        if self._connection is not None:
            self._connection.disconnect()
            self._connection = None

    # ==== Setters ====

    def update_symbols(self) -> tuple[int, Error]:
        """
        Update global variables and functions in the debugger.

        This always invalidates the cache for global variables and
        function headers, and requests them from the plugin.

        Returns the amount of synced symbols and an error diagnostic.

        Possible error values:
            NO_CONNECTION
            BINARY_NOT_LOADED
            NOT_ALIVE
            DEBUGGER_NOT_SUPPORTED

        FIXME: Currently they are all 8 bytes in size.
        """
        # We need to bail even if we are connected, but the binary is not loaded into
        # the address space yet.
        if self._connection is None:
            return 0, Error.NO_CONNECTION

        if self._connection.binary_base_addr == -1:
            return 0, Error.BINARY_NOT_LOADED

        # Invalidate the two caches.
        self._function_headers = None
        self._global_vars = None

        if pwndbg.dbg.name() == pwndbg.dbg_mod.DebuggerType.LLDB:
            # Until we implement add_symbol_file for LLDB.
            return 0, Error.DEBUGGER_NOT_SUPPORTED

        try:
            inf: pwndbg.dbg_mod.Process = pwndbg.dbg.selected_inferior()
        except pwndbg.dbg_mod.NoInferior:
            # Should never happen because we already know that binary_base_address is set.
            return 0, Error.NOT_ALIVE

        if not inf.alive():
            # Should never happen because we already know that binary_base_address is set.
            return 0, Error.NOT_ALIVE

        # Remove old symbol file.
        # If we don't do this, the symbols will stack (run `info func` in GDB).
        self.remove_symbols(inf)

        global_vars: GlobalVariables | None = self.global_vars()
        func_headers: FunctionHeaders | None = self.function_headers()
        # (name, address)
        syms_to_add: list[tuple[str, int]] = []
        # To get rid of duplicates
        sym_name_set: set[str] = set()

        if func_headers is not None:
            for func in func_headers.funcs:
                syms_to_add.append((func.name, func.addr))
                sym_name_set.add(func.name)

        if global_vars is not None:
            for var in global_vars.vars:
                clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", var.name)
                # never re-add globals with the same name as a func
                if clean_name in sym_name_set:
                    continue

                syms_to_add.append((clean_name, var.addr))
                sym_name_set.add(clean_name)

        if not syms_to_add:
            return 0, Error.OK

        _, elf_path = tempfile.mkstemp(prefix="symbols-", suffix=".elf")
        elf = niche_elf.ELFFile(self._connection.binary_base_addr)

        for sym_name, sym_addr in syms_to_add:
            elf.add_generic_symbol(sym_name, sym_addr)

        elf.write(elf_path)
        inf.add_symbol_file(elf_path, self._connection.binary_base_addr)
        self._latest_symbol_file_path = elf_path
        # Delete the file after GDB closes the file descriptor.
        os.unlink(elf_path)
        return len(syms_to_add), Error.OK

    def _clean_type_str(self, type_str: str) -> str:
        # FIXME:
        # 1. this is too aggressive
        # 2. if we start adding types to the debugger then it doesn't matter
        # Copied from: https://github.com/mahaloz/decomp2dbg/blob/b23f2e232625c6ebe11b86c065c27b95da16aa3b/decomp2dbg/clients/gdb/gdb_client.py#L95
        if "__" in type_str:
            type_str = type_str.replace("__", "")
            idx = type_str.find("[")
            if idx != -1:
                type_str = type_str[:idx] + "_t" + type_str[idx:]
            else:
                type_str += "_t"
        type_str = type_str.replace("unsigned ", "u")

        return type_str

    def _try_setting_conv_var_with_type(self, name: str, value: str, type: str) -> bool:
        """
        Try setting a convenience variable with a type. If it fails try with void* .
        If that fails as well, thats okay, you can't win them all.

        Return True if we succeeded, False otherwise.
        """
        try:
            pwndbg.dbg.set_convenience_var(name, value, type)
            return True
        except Exception:
            pass

        try:
            pwndbg.dbg.set_convenience_var(name, value, "void*")
            return True
        except Exception:
            pass

        return False

    def update_function_variables(self) -> tuple[int, Error]:
        """
        Update debugger convnience varibles based on the function variables in the currently
        selected frame.

        This always fully invalidates the cache for function variables and requests
        them from the plugin.

        Returns:
            The number of variables we successfully updated in the debugger.
            An error diagnostic (NO_CONNECTION or NO_FRAME).

        FIXME: Currently this kinda doesn't work if it runs while we are in the function
        prologue. We should ideally run it only when we enter new functions and are past
        their prologues.
        """
        if self._connection is None:
            return 0, Error.NO_CONNECTION

        # We could do some updates without having a valid selected frame by using pwndbg.aglib.regs.sp ,
        # but this probably complicates the code uneccessarily (see some previous commits in the PR).
        # I'm simply not sure when exactly can selected_frame() actually return None.
        frame: pwndbg.dbg_mod.Frame | None = pwndbg.dbg.selected_frame()
        if frame is None:
            return 0, Error.NO_FRAME

        # Invalidate this whole cache.
        # We could invalidate just for frame.pc() for the purposes of this function, but we want to invalidate
        # this whole cache *somewhere* so non-local queries don't have stale data, and this function is a nice
        # place to do it.
        self._function_data.clear()

        rebased_vars: RebasedFuncVariables | None = self.get_function_vars_rebased_from_frame(frame)
        if rebased_vars is None:
            return 0, Error.OK

        nupdated: int = 0

        for reg_var in rebased_vars.reg_vars:
            cleaned_type: str = self._clean_type_str(reg_var.type)
            ok = self._try_setting_conv_var_with_type(
                reg_var.name, f"${reg_var.reg_name}", cleaned_type
            )
            nupdated += 1 if ok else 0

        for stack_var in rebased_vars.stack_vars:
            # Pointer to the type.
            cleaned_type = f"{self._clean_type_str(stack_var.type)}*"
            ok = self._try_setting_conv_var_with_type(
                stack_var.name, hex(stack_var.addr), cleaned_type
            )
            nupdated += 1 if ok else 0

        return nupdated, Error.OK

    # ==== Getters ====
    # All getters are either cheap (no RPC) operations, or cached.
    # The caching may be until stop, or until the cache is invalidated.

    def is_connected(self) -> bool:
        """
        Are we connected to a decompiler?

        Lightweight check, use a ping for an actual check.
        """
        return self._connection is not None

    def decompiler_id(self) -> DecompilerID | None:
        """
        Which decompiler are we connected to?
        """
        if self._connection is not None and self._decompiler_id is None:
            self._decompiler_id = _api_name_to_id[self._connection.versions["name"]]
        return self._decompiler_id

    def decompiler_name(self) -> str:
        """
        If we are connected, will return the name of the decompiler we are connected to.

        If we are not connected, will return "???".
        """
        decompilerid: DecompilerID | None = self.decompiler_id()
        if decompilerid is not None:
            return decompilerid.value
        return "???"

    def version_string(self) -> str | None:
        """
        Get a string with version information about the decompiler environment.
        """
        if self._connection is None:
            return None

        versions = self._connection.versions

        name: str = _api_name_to_id[versions["name"]].value
        ver: str = versions["version"]

        res = f"{name}: {ver}"
        # Add all other auxiliary information, no matter what it is.
        for key, value in versions.items():
            if key in {"name", "version"}:
                continue
            res += f"\n{name} {key}: {value}"

        return res

    def get_function_vars_rebased_from_frame(
        self, frame: pwndbg.dbg_mod.Frame
    ) -> RebasedFuncVariables | None:
        """
        Get function variables for the passed frame. Stack variables will have valid addresses rather than offsets.

        frame.pc() will be used to ask the debugger for the valid function variables. Note that it is possible that
        the same function returns different sets of variables at different PC's.

        frame.sp() and frame.start() are used to rebase stack variables based on decompiler-returned offsets. Register
        variables are unmodified.

        The RPC call to the decompiler when asking for variables is cached, but the rebasing is not, ergo this function
        call is relatively expensive.

        Arguments:
            frame: The frame to use for fetching variables.
        """
        if self._connection is None:
            return None

        addr = frame.pc()

        raw_func_data: FuncVariables | None = self.function_data(addr)
        if raw_func_data is None:
            return None

        try:
            inf = pwndbg.dbg.selected_inferior()
        except pwndbg.dbg_mod.NoInferior:
            return None

        if not inf.alive():
            return None

        # Nothing to do for registers
        new_stack_vars: list[RebasedStackVariable] = []

        frame_sp: int = frame.sp()
        frame_start: int | None = frame.start()

        for stack_var in raw_func_data.stack_vars:
            from_sp: int | None = stack_var.from_sp
            from_frame: int | None = stack_var.from_frame

            # We do not account for a stack going upwards. If you have that you have bigger issues.

            if from_sp is not None:
                # We prefer sp-offseted variables because calculating their actual address is more likely
                # to work.
                var_addr = int(frame_sp) + from_sp
                new_stack_vars.append(
                    RebasedStackVariable(name=stack_var.name, type=stack_var.type, addr=var_addr)
                )
            elif from_frame is not None and frame_start is not None:
                var_addr = frame_start - from_frame
                new_stack_vars.append(
                    RebasedStackVariable(name=stack_var.name, type=stack_var.type, addr=var_addr)
                )

        return RebasedFuncVariables(reg_vars=raw_func_data.reg_vars, stack_vars=new_stack_vars)

    def get_stack_var_dict_from_frame(self, frame: pwndbg.dbg_mod.Frame) -> dict[int, str]:
        """
        Ask the decompiler for stack variable offsets in this frame and resolve
        each variable to an actual address.

        The RPC call to the decompiler when asking for variables is cached, but the rebasing is not, and dict
        creating is not, ergo this function call is relatively expensive.

        Returns:
            A dictionary that maps (stack variable address) -> (stack variable name)
            for all variables in the given frame.
        """

        # The function will take care of connection checking etc.
        rebased_func_data: RebasedFuncVariables | None = self.get_function_vars_rebased_from_frame(
            frame
        )
        if not rebased_func_data:
            return {}

        result: dict[int, str] = {}
        for stack_var in rebased_func_data.stack_vars:
            result[stack_var.addr] = stack_var.name

        return result

    # FIXME: The implementation of cache_until tells me I shouldn't return mutable types
    # should I make a read-only dict class?
    @pwndbg.lib.cache.cache_until("stop")
    def get_stack_var_dict_all(self) -> dict[int, str]:
        """
        Take all valid stack frames (from the whole backtrace), ask the decompiler to
        figure out where they are, and map them to their actual addresses.

        You must not modify the object you got from this function (because of caching).

        Returns:
            A dictionary that maps (stack variable address) -> (stack variable name)
            for all currently valid stack frames.
        """
        if self._connection is None:
            return {}

        thread = pwndbg.dbg.selected_thread()
        if thread is None:
            return {}

        result: dict[int, str] = {}

        with thread.bottom_frame() as bottom_frame:
            cur_frame = bottom_frame
            # Crawl up the stack
            while cur_frame is not None:
                cur_variables = self.get_stack_var_dict_from_frame(cur_frame)
                # Merge dictionaries
                result = result | cur_variables
                cur_frame = cur_frame.parent()

        return result

    def decompile_pretty(self, mapped_addr: int, nlines: int) -> list[str] | None:
        """
        Get the prettified decompilation of a function.

        The following things are done:
        + syntax highlighting
        + '►' indicator at the current line
        + trimmed to only return `nlines` lines (surrounding the mapped_addr) (returns all lines if nlines == -1)

        Returns a list of strings each representing one line of the decompilation.
        """
        if self._connection is None:
            return None

        func_decomp: FuncDecompilationResult | None = self.decompile_raw(mapped_addr)

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

        # Ghidra often has this for some reason
        if decomp[0] == "":
            # This will make the line numbers off-by-one with the decompiler, but imo
            # saving screen space is more important.
            decomp = decomp[1:]
            # could be 0 or -1
            curr_line = (curr_line - 1) if curr_line > 0 else curr_line

        # Ghidra may return -1 (https://github.com/mahaloz/decomp2dbg/issues/131)
        # Cache the curr_line for this function if its valid.
        if curr_line == -1:
            if func_decomp.func_name in self.__func_curr_line:
                curr_line = self.__func_curr_line[func_decomp.func_name]
            else:
                curr_line = 0
        else:
            self.__func_curr_line[func_decomp.func_name] = curr_line

        formatted_decomp = pretty_print.format_source(list(decomp), nlines, curr_line)
        return formatted_decomp

    @pwndbg.lib.cache.cache_until("stop")
    def symbol_at_address(self, mapped_addr: int) -> str | None:
        """
        Returns name of a symbol (function or global variable) at given address,
        or None if there is nothing there.

        FIXME: Currently, global variables don't acknowledge their actual size.
        FIXME2: After update_symbols() is updated to acknowledge symbol sizes, this will be obsolete.
        """
        if self._connection is None:
            return None

        global_vars: GlobalVariables | None = self.global_vars()
        func_headers: FunctionHeaders | None = self.function_headers()

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

    def decompile_raw(self, mapped_addr: int) -> FuncDecompilationResult | None:
        """
        Returns the decompilation of the function which contains address `mapped_addr`.

        Generally you should use self.decompile_pretty().
        """
        # I intentionally didn't name this function just `decompile` to prevent
        # people from accidentally using it when there is a better alternative.
        if self._connection is not None:
            return self._connection.decompile(mapped_addr)
        return None

    def function_data(self, mapped_addr: int) -> FuncVariables | None:
        """
        Returns the variables of the function which contains address `mapped_addr`.

        The "offset" field of the stack variables is poorly defined.

        The register variables are quite best effort and do not actually take
        the asked for address into account. In other words, the output for these
        may be just plain wrong.

        Function arguments are included in these variables.
        """
        if self._connection is not None and mapped_addr not in self._function_data:
            # This is a wacky cache. We could cache per function-name,
            # but that is not semantically correct (e.g. DWARF spec, split variables..)
            # In fact, even caching per-address is not semantically correct per DWARF since
            # the variable's locations may depend arbitrarily on the values of various registers.
            # But oke, it's probably fine :)
            # I'm okay with allowing `= None` here because callers that want the actual most
            # recent value will always just invalidate this cache anyway.
            self._function_data[mapped_addr] = self._connection.function_data(mapped_addr)

        # Using .get() for the case when there is no connection and the key is not in the cache.
        return self._function_data.get(mapped_addr, None)

    def function_headers(self) -> FunctionHeaders | None:
        """
        Returns the name, address and size off all functions in the binary, sorted
        by address.
        """
        if self._connection is not None and self._function_headers is None:
            self._function_headers = self._connection.function_headers()
        return self._function_headers

    def global_vars(self) -> GlobalVariables | None:
        """
        Returns the name and address of all global variables in the binary, sorted
        by address.
        """
        if self._connection is not None and self._global_vars is None:
            self._global_vars = self._connection.global_vars()
        return self._global_vars

    def structs(self):
        raise NotImplementedError()

    def breakpoints(self):
        raise NotImplementedError()

    def focus_address(self, mapped_addr: int) -> bool:
        """
        Focus (jump to) this address in the decompiler.
        """
        if self._connection is not None:
            ans = self._connection.focus_address(mapped_addr)
            return ans if ans is not None else False
        return False


manager: IntegrationManager = IntegrationManager()
