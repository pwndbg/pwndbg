from __future__ import annotations

import argparse
import typing
from dataclasses import dataclass

from pwnlib.util.fiddling import ror
from pwnlib.util.packing import p64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u64

import pwndbg.aglib
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.tls
import pwndbg.chain
import pwndbg.color.memory
import pwndbg.color.message
import pwndbg.commands
import pwndbg.dintegration
import pwndbg.emu.emulator


@dataclass
class _ExitFunctionEntry:
    addr: int
    flavor: int
    fn: int
    arg: int
    dso_handle: int

    def __str__(self) -> str:
        match self.flavor:
            case 0:
                flavor_str = "ef_free"
            case 1:
                flavor_str = "ef_us"
            case 2:
                flavor_str = "ef_on"
            case 3:
                flavor_str = "ef_at"
            case 4:
                flavor_str = "ef_cxa"
            case _:
                flavor_str = "unknown"

        string = f"{pwndbg.color.memory.get(self.addr)} [{flavor_str} ({self.flavor})]"
        if flavor_str in {"ef_on", "ef_cxa", "ef_at", "unknown"}:
            decomp_stack_vars = pwndbg.dintegration.manager.get_stack_var_dict_all()
            fn_str = pwndbg.color.memory.get_address_and_symbol(self.fn, decomp_stack_vars)
            string += f": {fn_str}"
        if flavor_str in {"ef_on", "ef_cxa", "unknown"}:
            string += f" [arg = {pwndbg.chain.format(self.arg)}"
        if flavor_str in {"ef_cxa", "unknown"}:
            string += f", dso_handle = {pwndbg.color.memory.get(self.dso_handle)}]"
        elif flavor_str == "ef_on":
            string += "]"

        return string


@dataclass
class _TlsDtorEntry:
    address: int
    func: int
    obj: int
    map: int

    def __str__(self) -> str:
        decomp_stack_vars = pwndbg.dintegration.manager.get_stack_var_dict_all()
        string = f"{pwndbg.color.memory.get(self.address)}: "
        string += pwndbg.color.memory.get_address_and_symbol(self.func, decomp_stack_vars)
        string += f" [obj = {pwndbg.chain.format(self.obj)}"
        string += f", map = {pwndbg.color.memory.get(self.map)}]"
        return string


def _ptr_demangle(pointer_guard: int, ptr: int) -> int:
    if pwndbg.aglib.arch.name in {"x86-64", "i386"}:
        return (
            typing.cast(int, ror(ptr, pwndbg.aglib.arch.ptrsize * 2 + 1, pwndbg.aglib.arch.ptrbits))
            ^ pointer_guard
        ) & pwndbg.aglib.arch.ptrmask
    return ptr ^ pointer_guard


def _get_pointer_guard() -> int | None:
    if pwndbg.aglib.arch.name in {"x86-64", "i386"}:
        tls_addr = (
            pwndbg.aglib.tls.find_address_with_register()
            or pwndbg.aglib.tls.find_address_with_pthread_self()
        )
        if tls_addr is None:
            print(pwndbg.color.message.error("Failed to get TLS address"))
            return None
        pointer_guard_offset = pwndbg.aglib.arch.ptrsize * 6
        return pwndbg.aglib.memory.read_pointer_width(tls_addr + pointer_guard_offset)
    if pwndbg.aglib.arch.name in {"aarch64", "arm"}:
        pointer_chk_guard = pwndbg.aglib.symbol.lookup_symbol(
            "__pointer_chk_guard"
        ) or pwndbg.aglib.symbol.lookup_symbol("__pointer_chk_guard_local")
        if pointer_chk_guard is None:
            print(
                pwndbg.color.message.error(
                    "Could not find __pointer_chk_guard or __pointer_chk_guard_local symbols"
                )
            )
            return None
        return pwndbg.aglib.memory.read_pointer_width(int(pointer_chk_guard))
    print(
        pwndbg.color.message.error(
            f"Don't know how to get pointer_guard on {pwndbg.aglib.arch.name}"
        )
    )
    return None


def _get_exit_funcs_from_emulator() -> int | None:
    exit_addr = pwndbg.aglib.symbol.lookup_symbol("exit")
    if exit_addr is None:
        print(pwndbg.color.message.error("Failed to get address of exit"))
        return None
    emulator = pwndbg.emu.emulator.Emulator()
    if pwndbg.aglib.arch.name == "i386":
        emulator.update_pc(int(exit_addr))
        emulator.single_step()  # call mov eax, [esp] function
        emulator.until_jump()  # ret
        emulator.until_jump()  # call __run_exit_handlers
        esp = emulator.read_register("esp")
        if esp is None:
            print(pwndbg.color.message.error("Failed to read ESP register"))
            return None
        exit_funcs_ptr_bytes = emulator.read_memory(esp + 8, 4)
        if exit_funcs_ptr_bytes is None:
            print(pwndbg.color.message.error("Failed to read &__exit_funcs from stack"))
            return None
        exit_funcs_ptr = typing.cast(int, u32(exit_funcs_ptr_bytes, "little"))

    else:
        emulator.until_jump(int(exit_addr))
        abi = pwndbg.aglib.arch.function_abi
        if abi is None:
            print(pwndbg.color.message.error("arch.function_abi is None"))
            return None
        second_arg_reg = abi.register_arguments[1]
        exit_funcs_ptr = emulator.read_register(second_arg_reg)
        if exit_funcs_ptr is None:
            print(
                pwndbg.color.message.error(
                    f"Failed to read second argument register ({second_arg_reg})"
                )
            )
            return None
    return exit_funcs_ptr


def _get_tls_dtor_list_from_emulator() -> int | None:
    call_tls_dtors = pwndbg.aglib.symbol.lookup_symbol("__call_tls_dtors")
    tls_addr = (
        pwndbg.aglib.tls.find_address_with_register()
        or pwndbg.aglib.tls.find_address_with_pthread_self()
    )
    if call_tls_dtors is None:
        print(pwndbg.color.message.error("Failed to get address of __call_tls_dtors"))
        return None
    emulator = pwndbg.emu.emulator.Emulator()
    emulator.update_pc(int(call_tls_dtors))
    if pwndbg.aglib.arch.name == "x86-64":
        while True:
            inst_addr, _ = emulator.single_step()
            if inst_addr is None:
                print(
                    pwndbg.color.message.error(
                        f"Emulator failed to execute __call_tls_dtors instruction at {hex(emulator.pc())}"
                    )
                )
                return None
            inst = pwndbg.aglib.disasm.disassembly.get(inst_addr, 1, emulator)
            if len(inst) < 1:
                print(pwndbg.color.message.error("Failed to disassemble __call_tls_dtors"))
                return None
            inst = inst[0]
            read, _ = inst.cs_insn.regs_access()
            read_names: list[str] = [str(inst.cs_insn.reg_name(r)) for r in read]
            if len(read_names) != 2:
                continue
            try:
                fs_idx = read_names.index("fs")
            except ValueError:
                continue
            offset_reg = read_names[(fs_idx + 1) % 2]
            offset = emulator.read_register(offset_reg)
            if offset is None:
                print(pwndbg.color.message.error(f"Failed to read offset from {offset_reg}"))
                return None
            offset = typing.cast(int, u64(p64(offset, sign="unsigned"), sign="signed"))
            return tls_addr + offset
    return None


def _list_exit_handlers(pointer_guard: int, exit_funcs: int) -> list[_ExitFunctionEntry]:
    handlers: list[_ExitFunctionEntry] = []
    cur_exit_function_list = exit_funcs
    while True:
        if cur_exit_function_list == 0:
            break
        num_handlers = pwndbg.aglib.memory.read_pointer_width(
            cur_exit_function_list + pwndbg.aglib.arch.ptrsize
        )
        for i in reversed(range(num_handlers)):
            exit_function_struct_base = cur_exit_function_list + pwndbg.aglib.arch.ptrsize * (
                2 + 4 * i
            )
            flavor = pwndbg.aglib.memory.read_pointer_width(exit_function_struct_base)
            fn = _ptr_demangle(
                pointer_guard,
                pwndbg.aglib.memory.read_pointer_width(
                    exit_function_struct_base + pwndbg.aglib.arch.ptrsize
                ),
            )
            arg = pwndbg.aglib.memory.read_pointer_width(
                exit_function_struct_base + pwndbg.aglib.arch.ptrsize * 2
            )
            dso_handle = pwndbg.aglib.memory.read_pointer_width(
                exit_function_struct_base + pwndbg.aglib.arch.ptrsize * 3
            )
            handlers.append(
                _ExitFunctionEntry(exit_function_struct_base, flavor, fn, arg, dso_handle)
            )
        # update to cur_exit_function_list->next
        cur_exit_function_list = pwndbg.aglib.memory.read_pointer_width(cur_exit_function_list)
    return handlers


def _list_tls_dtors(pointer_guard: int, tls_dtor_list: int) -> list[_TlsDtorEntry]:
    cur_tls_dtor = pwndbg.aglib.memory.read_pointer_width(tls_dtor_list)
    dtors: list[_TlsDtorEntry] = []
    while cur_tls_dtor != 0:
        func = _ptr_demangle(pointer_guard, pwndbg.aglib.memory.read_pointer_width(cur_tls_dtor))
        obj = pwndbg.aglib.memory.read_pointer_width(cur_tls_dtor + pwndbg.aglib.arch.ptrsize)
        map = pwndbg.aglib.memory.read_pointer_width(cur_tls_dtor + pwndbg.aglib.arch.ptrsize * 2)
        dtors.append(_TlsDtorEntry(cur_tls_dtor, func, obj, map))
        cur_tls_dtor = pwndbg.aglib.memory.read_pointer_width(
            cur_tls_dtor + pwndbg.aglib.arch.ptrsize * 3
        )
    return dtors


parser = argparse.ArgumentParser(description="List currently registered glibc exit handlers.")


@pwndbg.commands.Command(
    parser, category=pwndbg.commands.CommandCategory.LINUX, aliases=["exitfuncs"]
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "i386", "aarch64", "arm"])
def exithandlers() -> None:
    pointer_guard = _get_pointer_guard()
    if pointer_guard is None:
        print(pwndbg.color.message.error("Failed to get pointer_guard"))
        return
    print(f"pointer_guard: {pwndbg.color.message.notice(hex(pointer_guard))}")
    exit_funcs_ptr = (
        pwndbg.aglib.symbol.lookup_symbol("__exit_funcs") or _get_exit_funcs_from_emulator()
    )
    if exit_funcs_ptr is None:
        print(pwndbg.color.message.error("Failed to get address of __exit_funcs"))
        return
    exit_funcs = pwndbg.aglib.memory.read_pointer_width(int(exit_funcs_ptr))
    print(f"\n__exit_funcs: {pwndbg.color.memory.get(exit_funcs)}")
    print("Registered __exit_funcs handlers:")
    exit_handlers = _list_exit_handlers(pointer_guard, exit_funcs)
    for entry in exit_handlers:
        print(str(entry))

    tls_dtor_list = (
        pwndbg.aglib.symbol.lookup_symbol("tls_dtor_list") or _get_tls_dtor_list_from_emulator()
    )
    if tls_dtor_list is None:
        print(pwndbg.color.message.error("Failed to locate tls_dtor_list"))
        return
    print(f"\ntls_dtor_list: {pwndbg.color.memory.get(tls_dtor_list)}")
    tls_dtors = _list_tls_dtors(pointer_guard, int(tls_dtor_list))
    print("Registered tls_dtor handlers:")
    for dtor in tls_dtors:
        print(str(dtor))
