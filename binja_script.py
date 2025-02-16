from __future__ import annotations

import ctypes
import os
import sys
import threading
import xmlrpc.client
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from xmlrpc.server import SimpleXMLRPCRequestHandler
from xmlrpc.server import SimpleXMLRPCServer

import binaryninja
from binaryninja.enums import RegisterValueType
from binaryninja.enums import VariableSourceType

# Allow large integers to be transmitted
xmlrpc.client.MAXINT = 10**100
xmlrpc.client.MININT = -(10**100)


host = os.environ.get("PWNDBG_BINJA_SERVER_HOST", "127.0.0.1")
port = int(os.environ.get("PWNDBG_BINJA_SERVER_PORT", "31337"))

logger = binaryninja.log.Logger(0, "pwndbg-integration")


class CustomLogHandler(SimpleXMLRPCRequestHandler):
    def log_message(self, format: str, *args: Any):
        logger.log_debug(format % args)


# get the earliest-starting function that contains a given address
def get_widest_func(bv: binaryninja.BinaryView, addr: int) -> binaryninja.Function | None:
    funcs = bv.get_functions_containing(addr)
    if len(funcs) == 0:
        return None
    return min(funcs, key=lambda f: f.start)


# workaround for BinaryView.add_tag not supporting auto tags
def add_data_tag(
    bv: binaryninja.BinaryView, addr: int, name: str, desc: str, auto: bool = False
) -> None:
    if auto:
        tag = binaryninja.core.BNCreateTag(bv.get_tag_type(name).handle, desc)
        binaryninja.core.BNAddTag(bv.handle, tag, False)
        binaryninja.core.BNAddAutoDataTag(bv.handle, addr, tag)
    else:
        bv.add_tag(addr, name, desc)


# try to add a function tag to the widest function containing the address
# if there are none, resort to a data tag instead
def add_tag_at_addr(
    bv: binaryninja.BinaryView, addr: int, name: str, desc: str, auto: bool = False
) -> None:
    f = get_widest_func(bv, addr)
    if f is None:
        add_data_tag(bv, addr, name, desc, auto=auto)
    else:
        f.add_tag(name, desc, addr=addr, auto=auto)


# workaround for there to be no way to get all address tags in the python API
def get_tag_refs(bv: binaryninja.BinaryView, ty: str) -> List[binaryninja.core.BNTagReference]:
    tag_type = bv.get_tag_type(ty)
    count = binaryninja.core.BNGetAllTagReferencesOfTypeCount(bv.handle, tag_type.handle)
    ref_ptr = binaryninja.core.BNGetAllTagReferencesOfType(
        bv.handle, tag_type.handle, ctypes.c_ulong(count)
    )
    return ref_ptr[:count]


def remove_tag_ref(bv: binaryninja.BinaryView, ref: binaryninja.core.BNTagReference):
    binaryninja.core.BNRemoveTagReference(bv.handle, ref)


def count_pointers(ty: Any) -> Tuple[str, int]:
    derefcnt = 0
    while isinstance(ty, binaryninja.types.PointerType):
        ty = ty.target
        derefcnt += 1
    return (str(ty), derefcnt)


to_register = []


def should_register(f):
    to_register.append(f.__name__)
    return f


class ServerHandler:
    bv: binaryninja.BinaryView

    def __init__(self, bv: binaryninja.BinaryView):
        self.bv = bv

    # initialize a binaryview if not already initialized, e.g. add a tag type
    def init(self) -> None:
        tag_types = {"pwndbg-pc": "➡️", "pwndbg-bp": "🔴"}
        for k, v in tag_types.items():
            if k not in self.bv.tag_types:
                self.bv.create_tag_type(k, v)

    @should_register
    def clear_pc_tag(self) -> None:
        """
        Clear all instances of the 'current pc' tag.
        """
        for t in get_tag_refs(self.bv, "pwndbg-pc"):
            remove_tag_ref(self.bv, t)

    @should_register
    def navigate_to(self, addr: int) -> None:
        """
        Navigate to a specified address.
        """
        self.bv.navigate(self.bv.view, addr)

    @should_register
    def update_pc_tag(self, new_pc: int) -> None:
        """
        Sets the 'current pc' tag to the specified address, and clears the old ones.
        """
        self.clear_pc_tag()
        add_tag_at_addr(self.bv, new_pc, "pwndbg-pc", "current pc", auto=True)

    @should_register
    def get_bp_tags(self) -> List[int]:
        """
        Gets a list of all addresses with a breakpoint tag.
        """
        return [t.addr for t in get_tag_refs(self.bv, "pwndbg-bp")]

    @should_register
    def get_symbol(self, addr: int) -> str | None:
        """
        Gets the symbol at exactly the specified address.
        """
        sym = self.bv.get_symbol_at(addr)
        if sym is None:
            return None
        return sym.full_name

    @should_register
    def get_func_info(self, addr: int) -> Tuple[str, int] | None:
        """
        Gets the widest function containing the specified address.

        Returns a (function name, offset from start) tuple.
        """
        func = get_widest_func(self.bv, addr)
        if func is None:
            return None
        return (func.symbol.full_name, func.start)

    @should_register
    def get_data_info(self, addr: int) -> Tuple[str, int] | None:
        """
        Gets the data variable containing the specified address.

        Returns a (variable name, offset from start) tuple.
        """
        dv = self.bv.get_data_var_at(addr)
        if dv is None:
            return None
        if dv.symbol is not None:
            return (dv.symbol.full_name, dv.address)
        return (dv.name or f"data_{dv.address:x}", dv.address)

    @should_register
    def get_comments(self, addr: int) -> List[str]:
        """
        Gets a list of all comments at a specified address.
        """
        ret = []
        func_list = sorted(self.bv.get_functions_containing(addr), key=lambda f: f.start)
        for f in func_list:
            ret += f.get_comment_at(addr).split("\n")
        ret += self.bv.get_comment_at(addr).split("\n")
        # remove empty lines and prepend double slash
        return ["// " + x for x in ret if x]

    @should_register
    def decompile_func(
        self, addr: int, level: str
    ) -> List[Tuple[int, List[Tuple[str, str]]]] | None:
        """
        Gets the decompilation of a function at a specified IL level.

        Returns a list of (address, token) tuples, where each token is a (text, type) tuple.
        """
        func = get_widest_func(self.bv, addr)
        if func is None:
            return None
        orig_func = func
        if level == "disasm":
            pass
        elif level == "llil":
            func = func.llil_if_available
        elif level == "mlil":
            func = func.mlil_if_available
        elif level == "hlil":
            func = func.hlil_if_available
        else:
            raise ValueError(
                f"{level!r} is not a recognized IL level. Supported values are: disasm, llil, mlil, hlil."
            )
        if func is None:
            return None
        if level == "hlil":
            lines = func.root.lines
        else:
            if level == "disasm":
                lines = [
                    binaryninja.function.DisassemblyTextLine(tok, addr)
                    for (tok, addr) in func.instructions
                ]
            else:
                lines = [
                    binaryninja.function.DisassemblyTextLine(line.tokens, line.address, line)
                    for line in func.instructions
                ]
            lines = binaryninja.function.DisassemblyTextRenderer(func).post_process_lines(
                orig_func.lowest_address,
                orig_func.highest_address - orig_func.lowest_address,
                lines,
            )

        return [
            (line.address, [(tok.text, tok.type.name) for tok in line.tokens]) for line in lines
        ]

    @should_register
    def get_func_type(
        self, addr: int
    ) -> Tuple[Tuple[str, int, str], List[Tuple[str, int, str]]] | None:
        """
        Gets the type signature of a function.

        Returns a (return type, list of argument types) tuples,
        where the return type is a (type, pointer count, function name) tuple,
        and the argument types are (type, pointer count, argument name) tuples.
        """
        f = self.bv.get_function_at(addr)
        if f is None:
            return None
        ret_ty = (*count_pointers(f.return_type), f.name)
        arg_tys = [(*count_pointers(arg.type), arg.name) for arg in f.parameter_vars]
        return (ret_ty, arg_tys)

    @should_register
    def get_symbol_addr(self, sym: str) -> int | None:
        """
        Gets the address of a symbol.
        """
        syms = self.bv.get_symbols_by_name(sym)
        if syms:
            return syms[0].address
        raw = self.bv.get_symbol_by_raw_name(sym)
        if raw:
            return raw.address
        try:
            if sym.startswith("data_"):
                return int(sym[5:], 16)
            if sym.startswith("sub_"):
                return int(sym[4:], 16)
        except ValueError:
            return None
        return None

    @should_register
    def parse_expr(self, expr: str, magic_vals: Dict[str, int]) -> int | None:
        """
        Parses and evaluates a Binary Ninja expression given a dictionary of magic values.

        Check docs of BinaryView.parse_expression for more info.
        """
        try:
            self.bv.add_expression_parser_magic_values(
                list(magic_vals.keys()), list(magic_vals.values())
            )
            return self.bv.parse_expression(expr)
        except ValueError:
            return None

    @should_register
    def get_var_offset_from_sp(self, pc: int, var_name: str) -> Tuple[int, int] | None:
        """
        Gets the offset of a stack variable from the stack pointer, given the current pc and variable name.

        Returns a (confidence, offset) tuple.
        """
        f = get_widest_func(self.bv, pc)
        if f is None:
            return None
        v = f.get_variable_by_name(var_name)
        if v is None or v.source_type != VariableSourceType.StackVariableSourceType:
            return None
        sp_val = f.get_reg_value_at(pc, f.arch.stack_pointer)
        if sp_val.type != RegisterValueType.StackFrameOffset:
            return None
        return (sp_val.confidence, v.storage - sp_val.value)

    @should_register
    def get_stack_var_name(
        self, pc: int, regs: List[Tuple[str, int]], addr: int
    ) -> Tuple[int, str, str] | None:
        """
        Gets the name of a stack variable, given the current pc,
        list of (name, value) register pairs, and address of the stack variable.

        The frame base is computed from the first register in the list that Binary Ninja
        determines to be a fixed offset from the frame base. Registers that should probably
        be included are the stack pointer and frame pointer.

        Returns a (confidence, function name, variable name) tuple.
        """
        f = get_widest_func(self.bv, pc)
        if f is None:
            return None
        valid_regs = []
        for name, val in regs:
            static_val = f.get_reg_value_at(pc, name)
            if static_val.type != RegisterValueType.StackFrameOffset:
                continue
            valid_regs.append((val - static_val.value, static_val.confidence))
            # break early if we're at max confidence
            if static_val.confidence == 255:
                break
        if not valid_regs:
            return None
        (frame_base, conf) = max(valid_regs, key=lambda x: x[1])
        v = f.get_stack_var_at_frame_offset(addr - frame_base, pc)
        if v is None:
            return None
        return (conf, f.name, v.name)

    @should_register
    def get_base(self) -> int:
        """
        Gets the base address of the BinaryView.
        """
        return self.bv.start

    @should_register
    def get_py_version(self) -> str:
        """
        Gets Binary Ninja's python version.
        """
        return sys.version

    @should_register
    def get_version(self) -> str:
        """
        Gets Binary Ninja's version.
        """
        return binaryninja.core_version()


server: SimpleXMLRPCServer | None = None
handler: ServerHandler | None = None


def start_server(bv: binaryninja.BinaryView) -> None:
    global server

    if server is not None:
        stop_server(bv)

    handler = ServerHandler(bv)
    handler.init()

    server = SimpleXMLRPCServer((host, port), requestHandler=CustomLogHandler, allow_none=True)
    server.register_introspection_functions()

    for f in to_register:
        server.register_function(getattr(handler, f))

    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    logger.log_info(f"XML-RPC server listening on http://{host}:{port}")


def stop_server(bv: binaryninja.BinaryView) -> None:
    global server

    if server is None:
        return

    server.shutdown()
    server.server_close()
    server = None


def toggle_breakpoint(bv: binaryninja.BinaryView, addr: int) -> None:
    found = False
    for t in get_tag_refs(bv, "pwndbg-bp"):
        if t.addr == addr:
            remove_tag_ref(bv, t)
            found = True
    if not found:
        add_tag_at_addr(bv, addr, "pwndbg-bp", "GDB breakpoint", auto=False)


binaryninja.plugin.PluginCommand.register(
    "pwndbg\\Start integration on current view",
    "Start pwndbg integration on current view.",
    start_server,
)
binaryninja.plugin.PluginCommand.register(
    "pwndbg\\Stop integration", "Stop pwndbg integration.", stop_server
)
binaryninja.plugin.PluginCommand.register_for_address(
    "pwndbg\\Toggle breakpoint here",
    "Toggles a GDB breakpoint at the current address.",
    toggle_breakpoint,
)
