from __future__ import annotations

import argparse
import typing
from dataclasses import dataclass

from pwnlib.util.fiddling import ror
from pwnlib.util.packing import p32
from pwnlib.util.packing import p64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u64
from rich.table import Table

import pwndbg.aglib
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.tls
import pwndbg.aglib.typeinfo
import pwndbg.chain
import pwndbg.color.memory
import pwndbg.commands
import pwndbg.dintegration
import pwndbg.emu.emulator
import pwndbg.libc
import pwndbg.rich
from pwndbg.color import blue
from pwndbg.color import message
from pwndbg.dbg_mod import Value


@dataclass
class _ExitFunctionEntry:
    addr: int
    flavor: int
    fn: int
    arg: int
    dso_handle: int

    @staticmethod
    def read(addr: int, pointer_guard: int) -> _ExitFunctionEntry:
        # https://elixir.bootlin.com/glibc/glibc-2.43/source/stdlib/exit.h#L34
        # always assume the cxa variant to simply things, as this is the largest and the field types match anyway
        # struct exit_function
        # {
        #   long int flavor
        #   union
        #     {
        #       ...
        #       struct
        #         {
        #           void (*fn) (void *arg, int status);
        #           void *arg;
        #           void *dso_handle;
        #         } cxa;
        #     } func;
        # };
        flavor_offset = 0
        fn_offset = (
            flavor_offset
            + pwndbg.aglib.typeinfo.long.sizeof
            + (pwndbg.aglib.arch.ptrsize - pwndbg.aglib.typeinfo.long.sizeof)  # padding
        )
        arg_offset = fn_offset + pwndbg.aglib.arch.ptrsize
        dso_offset = arg_offset + pwndbg.aglib.arch.ptrsize
        if (debug_type := pwndbg.aglib.typeinfo.lookup_types("exit_function")) is not None:
            flavor_offset = debug_type.offsetof("flavor") or flavor_offset
            # offsetof *should* recursively search union members
            fn_offset = debug_type.offsetof("fn") or fn_offset
            arg_offset = debug_type.offsetof("arg") or arg_offset
            dso_offset = debug_type.offsetof("dso_handle") or dso_offset

        flavor = pwndbg.aglib.memory.readtype(pwndbg.aglib.typeinfo.long, addr + flavor_offset)
        fn = _ptr_demangle(
            pointer_guard,
            pwndbg.aglib.memory.read_pointer_width(addr + fn_offset),
        )
        arg = pwndbg.aglib.memory.read_pointer_width(addr + arg_offset)
        dso_handle = pwndbg.aglib.memory.read_pointer_width(addr + dso_offset)
        return _ExitFunctionEntry(addr, flavor, fn, arg, dso_handle)

    @staticmethod
    def size() -> int:
        if (debug_type := pwndbg.aglib.typeinfo.lookup_types("exit_function")) is not None:
            return debug_type.sizeof
        flavor_offset = 0
        fn_offset = (
            flavor_offset
            + pwndbg.aglib.typeinfo.long.sizeof
            + (pwndbg.aglib.arch.ptrsize - pwndbg.aglib.typeinfo.long.sizeof)  # padding
        )
        arg_offset = fn_offset + pwndbg.aglib.arch.ptrsize
        dso_offset = arg_offset + pwndbg.aglib.arch.ptrsize
        return dso_offset + pwndbg.aglib.arch.ptrsize


@dataclass
class _TlsDtorEntry:
    address: int
    func: int
    obj: int
    map: int
    next: int

    @staticmethod
    def read(addr: int, pointer_guard: int) -> _TlsDtorEntry:
        # https://elixir.bootlin.com/glibc/glibc-2.43/source/stdlib/cxa_thread_atexit_impl.c#L82
        # struct dtor_list
        # {
        #   dtor_func func;
        #   void *obj;
        #   struct link_map *map;
        #   struct dtor_list *next;
        # };
        func_offset = 0
        obj_offset = func_offset + pwndbg.aglib.arch.ptrsize
        map_offset = obj_offset + pwndbg.aglib.arch.ptrsize
        next_offset = map_offset + pwndbg.aglib.arch.ptrsize
        if (debug_type := pwndbg.aglib.typeinfo.lookup_types("dtor_list")) is not None:
            func_offset = debug_type.offsetof("func") or func_offset
            obj_offset = debug_type.offsetof("obj") or obj_offset
            map_offset = debug_type.offsetof("map") or map_offset
            next_offset = debug_type.offsetof("next") or next_offset
        func = _ptr_demangle(
            pointer_guard, pwndbg.aglib.memory.read_pointer_width(addr + func_offset)
        )
        obj = pwndbg.aglib.memory.read_pointer_width(addr + obj_offset)
        map = pwndbg.aglib.memory.read_pointer_width(addr + map_offset)
        next = pwndbg.aglib.memory.read_pointer_width(addr + next_offset)
        return _TlsDtorEntry(addr, func, obj, map, next)


def _ptr_demangle(pointer_guard: int, ptr: int) -> int:
    # list of PTR_DEMANGLE macros: https://elixir.bootlin.com/glibc/glibc-2.43/A/ident/PTR_DEMANGLE
    if pwndbg.aglib.arch.name in {"x86-64", "i386"}:
        # https://elixir.bootlin.com/glibc/glibc-2.43/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L63
        return (
            typing.cast(int, ror(ptr, pwndbg.aglib.arch.ptrsize * 2 + 1, pwndbg.aglib.arch.ptrbits))
            ^ pointer_guard
        ) & pwndbg.aglib.arch.ptrmask
    if pwndbg.aglib.arch.name in {"aarch64", "arm", "sparc", "powerpc", "loongarch64", "s390x"}:
        # https://elixir.bootlin.com/glibc/glibc-2.43/source/sysdeps/arm/pointer_guard.h#L63
        return ptr ^ pointer_guard
    # all other architectures use the generic implementation:
    # https://elixir.bootlin.com/glibc/glibc-2.43/source/sysdeps/generic/pointer_guard.h#L26
    return ptr


def _get_pointer_guard() -> int | None:
    if pwndbg.aglib.arch.name in {"x86-64", "i386"}:  # x86 stores pointer_guard in TLS
        tls_addr = (
            pwndbg.aglib.tls.find_address_with_register()
            or pwndbg.aglib.tls.find_address_with_pthread_self()
        )
        if tls_addr is None:
            print(message.error("Failed to get TLS address"))
            return None

        # https://elixir.bootlin.com/glibc/glibc-2.43/source/sysdeps/x86_64/nptl/tls.h#L42
        # https://elixir.bootlin.com/glibc/glibc-2.43/source/sysdeps/i386/nptl/tls.h#L33
        # 5 pointers + 1 int + padding
        pointer_guard_offset = (
            pwndbg.aglib.typeinfo.sint.sizeof
            + (pwndbg.aglib.arch.ptrsize - pwndbg.aglib.typeinfo.sint.sizeof)  # padding
            + pwndbg.aglib.arch.ptrsize * 5
        )
        if (tcbhead_t := pwndbg.aglib.typeinfo.lookup_types("tcbhead_t")) is not None:
            pointer_guard_offset = tcbhead_t.offsetof("pointer_guard") or pointer_guard_offset
        return pwndbg.aglib.memory.read_pointer_width(tls_addr + pointer_guard_offset)

    if pwndbg.aglib.arch.name in {"aarch64", "arm"}:  # arm stores it in __pointer_chk_guard(_local)
        pointer_chk_guard = pwndbg.aglib.symbol.lookup_symbol(
            "__pointer_chk_guard"
        ) or pwndbg.aglib.symbol.lookup_symbol("__pointer_chk_guard_local")
        if pointer_chk_guard is None:
            print(
                message.error(
                    "Could not find __pointer_chk_guard or __pointer_chk_guard_local symbols"
                )
            )
            return None
        # pointer_chk_guard is a uintptr_t so cast symbol addr to uint **
        return int(
            pointer_chk_guard.cast(pwndbg.aglib.typeinfo.uint.pointer().pointer()).dereference()
        )
    print(message.error(f"Don't know how to get pointer_guard on {pwndbg.aglib.arch.name}"))
    return None


def _get_exit_funcs_from_emulator() -> int | None:
    exit_addr = pwndbg.aglib.symbol.lookup_symbol("exit")
    if exit_addr is None:
        print(message.error("Failed to get address of exit"))
        return None
    emulator = pwndbg.emu.emulator.Emulator()
    if pwndbg.aglib.arch.name == "i386":
        emulator.update_pc(int(exit_addr))
        emulator.single_step()  # call mov eax, [esp] function
        emulator.until_jump()  # ret
        emulator.until_jump()  # call __run_exit_handlers
        esp = emulator.read_register("esp")
        if esp is None:
            print(message.error("Failed to read ESP register"))
            return None
        exit_funcs_ptr_bytes = emulator.read_memory(esp + 8, 4)
        if exit_funcs_ptr_bytes is None:
            print(message.error("Failed to read &__exit_funcs from stack"))
            return None
        exit_funcs_ptr = typing.cast(int, u32(exit_funcs_ptr_bytes, "little"))

    else:
        emulator.until_jump(int(exit_addr))
        abi = pwndbg.aglib.arch.function_abi
        if abi is None:
            print(message.error("arch.function_abi is None"))
            return None
        second_arg_reg = abi.register_arguments[1]
        exit_funcs_ptr = emulator.read_register(second_arg_reg)
        if exit_funcs_ptr is None:
            print(message.error(f"Failed to read second argument register ({second_arg_reg})"))
            return None
    return exit_funcs_ptr


def _get_tls_dtor_list_offset_from_emulator_x86_64(
    emulator: pwndbg.emu.emulator.Emulator,
) -> int | None:
    while True:
        inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(emulator.pc())
        if inst is None:
            print(message.error("Failed to disassemble __call_tls_dtors"))
            return None
        read, _ = inst.cs_insn.regs_access()
        read_names: list[str] = [str(inst.cs_insn.reg_name(r)) for r in read]
        if len(read_names) == 2 and "fs" in read_names:
            offset_reg = [r for r in read_names if r != "fs"][0]
            offset = emulator.read_register(offset_reg)
            if offset is None:
                print(message.error(f"Failed to read offset from {offset_reg}"))
                return None
            return typing.cast(int, u64(p64(offset, sign="unsigned"), sign="signed"))
        emulator.single_step()


def _get_tls_dtor_list_offset_from_emulator_i386(
    emulator: pwndbg.emu.emulator.Emulator,
) -> int | None:
    while True:
        inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(emulator.pc())
        if inst is None:
            print(message.error("Failed to disassemble __call_tls_dtors"))
            return None
        read, _ = inst.cs_insn.regs_access()
        read_names: list[str] = [str(inst.cs_insn.reg_name(r)) for r in read]
        if len(read_names) == 2 and "gs" in read_names:
            offset_reg = [r for r in read_names if r != "gs"][0]
            offset = emulator.read_register(offset_reg)
            if offset is None:
                print(message.error(f"Failed to read offset from {offset_reg}"))
                return None
            return typing.cast(int, u32(p32(offset, sign="unsigned"), sign="signed"))
        emulator.single_step()


def _get_tls_dtor_list_offset_from_emulator_aarch64(
    emulator: pwndbg.emu.emulator.Emulator,
) -> int | None:
    while True:
        inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(emulator.pc())
        if inst is None:
            print(message.error("Failed to disassemble __call_tls_dtors"))
            return None
        if inst.mnemonic.lower() == "mrs" and "tpidr_el0" in inst.cs_insn.op_str.lower():
            _, written = inst.cs_insn.regs_access()
            if len(written) < 1:
                print(message.error("Failed to get write operand for mrs tpidr_el0 instruction"))
                return None
            tls_base_reg = str(inst.cs_insn.reg_name(written[0]))
            emulator.update_pc(inst.next)  # unicorn seems to not like emulating mrs
            # continue until something like ldr ... [tls, offset]
            while True:
                inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(emulator.pc())
                if inst is None:
                    print(message.error("Failed to disassemble __call_tls_dtors"))
                    return None
                read, _ = inst.cs_insn.regs_access()
                read_names = [str(inst.cs_insn.reg_name(r)) for r in read]
                if len(read_names) == 2 and tls_base_reg in read_names:
                    offset_reg = [r for r in read_names if r != tls_base_reg][0]
                    offset = emulator.read_register(offset_reg)
                    if offset is None:
                        print(message.error(f"Failed to read offset from {offset_reg}"))
                        return None
                    return typing.cast(int, u64(p64(offset, sign="unsigned"), sign="signed"))
                emulator.single_step()
        emulator.single_step()


def _get_tls_dtor_list_offset_from_emulator_arm(
    emulator: pwndbg.emu.emulator.Emulator, tls_addr: int
) -> int | None:
    bl_inst_addr, _ = emulator.until_jump()  # until what I think is a call to __aeabi_read_tp
    bl_inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(bl_inst_addr)
    if bl_inst is None:
        print(message.error("Failed to disassemble __call_tls_dtors"))
        return None
    emulator.update_pc(bl_inst.next)
    r0_reg_code = emulator.get_reg_enum("r0")
    if r0_reg_code is None:
        print(message.error("Failed to get unicorn register code for r0"))
        return None
    emulator.uc.reg_write(r0_reg_code, tls_addr)  # type: ignore[no-untyped-call, unused-ignore]
    while True:
        inst = pwndbg.aglib.disasm.disassembly.get_one_instruction(emulator.pc())
        if inst is None:
            print(message.error("Failed to disassemble __call_tls_dtors"))
            return None
        read, _ = inst.cs_insn.regs_access()
        read_names = [str(inst.cs_insn.reg_name(r)) for r in read]
        if len(read_names) == 2 and "r0" in read_names:
            offset_reg = [r for r in read_names if r != "r0"][0]
            offset = emulator.read_register(offset_reg)
            if offset is None:
                print(message.error(f"Failed to read offset from {offset_reg}"))
                return None
            return typing.cast(int, u32(p32(offset, sign="unsigned"), sign="signed"))
        emulator.single_step()


def _get_tls_dtor_list_from_emulator() -> int | None:
    call_tls_dtors = pwndbg.aglib.symbol.lookup_symbol("__call_tls_dtors")
    if call_tls_dtors is None:
        print(message.error("Failed to get address of __call_tls_dtors"))
        return None
    tls_addr = (
        pwndbg.aglib.tls.find_address_with_register()
        or pwndbg.aglib.tls.find_address_with_pthread_self()
    )
    if tls_addr is None:
        print(message.error("Failed to get TLS address"))
        return None
    emulator = pwndbg.emu.emulator.Emulator()
    emulator.update_pc(int(call_tls_dtors))
    offset = None
    match pwndbg.aglib.arch.name:
        case "x86-64":
            offset = _get_tls_dtor_list_offset_from_emulator_x86_64(emulator)
        case "i386":
            offset = _get_tls_dtor_list_offset_from_emulator_i386(emulator)
        case "aarch64":
            offset = _get_tls_dtor_list_offset_from_emulator_aarch64(emulator)
        case "arm":
            offset = _get_tls_dtor_list_offset_from_emulator_arm(emulator, tls_addr)

    if offset is None:
        print(
            message.error(
                "Failed to get TLS offset to tls_dtor_list from emulating __call_tls_dtors"
            )
        )
        return None
    return tls_addr + offset


def _list_exit_handlers(pointer_guard: int, initial_struct_addr: int) -> list[_ExitFunctionEntry]:
    handlers: list[_ExitFunctionEntry] = []
    # https://elixir.bootlin.com/glibc/glibc-2.43/source/stdlib/exit.h#L55
    # struct exit_function_list
    # {
    #   struct exit_function_list *next;
    #   size_t idx;
    #   struct exit_function fns[32];
    # };
    next_offset = 0
    idx_offset = pwndbg.aglib.arch.ptrsize
    fns_offset = idx_offset + pwndbg.aglib.typeinfo.size_t.sizeof
    if (debug_type := pwndbg.aglib.typeinfo.lookup_types("exit_function_list")) is not None:
        next_offset = debug_type.offsetof("next") or next_offset
        idx_offset = debug_type.offsetof("idx") or idx_offset
        fns_offset = debug_type.offsetof("fns") or fns_offset

    # this implements the loop in https://elixir.bootlin.com/glibc/glibc-2.43/source/stdlib/exit.c#L59
    cur_exit_function_list = initial_struct_addr
    while True:
        if cur_exit_function_list == 0:
            break
        idx = pwndbg.aglib.memory.readtype(
            pwndbg.aglib.typeinfo.size_t, cur_exit_function_list + idx_offset
        )
        for i in reversed(range(idx)):
            handlers.append(
                _ExitFunctionEntry.read(
                    cur_exit_function_list + fns_offset + _ExitFunctionEntry.size() * i,
                    pointer_guard,
                )
            )
        # update to cur_exit_function_list->next
        cur_exit_function_list = pwndbg.aglib.memory.read_pointer_width(
            cur_exit_function_list + next_offset
        )
    return handlers


def _list_tls_dtors(pointer_guard: int, tls_dtor_list: int) -> list[_TlsDtorEntry]:
    dtors: list[_TlsDtorEntry] = []
    func_offset = 0
    obj_offset = func_offset + pwndbg.aglib.arch.ptrsize
    map_offset = obj_offset + pwndbg.aglib.arch.ptrsize
    next_offset = map_offset + pwndbg.aglib.arch.ptrsize
    dtor_list_type = pwndbg.aglib.typeinfo.lookup_types("dtor_list")
    if dtor_list_type is not None:
        func_offset = dtor_list_type.offsetof("func") or func_offset
        obj_offset = dtor_list_type.offsetof("obj") or obj_offset
        map_offset = dtor_list_type.offsetof("map") or map_offset
        next_offset = dtor_list_type.offsetof("next") or next_offset

    cur_tls_dtor = pwndbg.aglib.memory.read_pointer_width(tls_dtor_list)
    while cur_tls_dtor != 0:
        entry = _TlsDtorEntry.read(cur_tls_dtor, pointer_guard)
        dtors.append(entry)
        cur_tls_dtor = entry.next
    return dtors


def _print_exit_handlers(handlers: list[_ExitFunctionEntry]) -> None:
    table = Table.grid()
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    for handler in handlers:
        sections = []
        match handler.flavor:
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
        sections.append(
            f"{pwndbg.color.memory.get(handler.addr)} \\[{flavor_str} ({handler.flavor})]"
        )
        if flavor_str in {"ef_on", "ef_cxa", "ef_at", "unknown"}:
            sections[0] += ": "
            decomp_stack_vars = pwndbg.dintegration.manager.get_stack_var_dict_all()
            fn_str = pwndbg.color.memory.get_address_and_symbol(handler.fn, decomp_stack_vars)
            sections.append(fn_str)
        else:
            sections.append("")
        if flavor_str in {"ef_on", "ef_cxa", "unknown"}:
            detail_string = f" \\[arg = {pwndbg.chain.format(handler.arg)}"
            if flavor_str in {"ef_cxa", "unknown"}:
                detail_string += f", dso_handle = {pwndbg.color.memory.get(handler.dso_handle)}]"
            elif flavor_str == "ef_on":
                detail_string += "]"
            sections.append(detail_string)
        else:
            sections.append("")
        table.add_row(*sections)
    print(pwndbg.rich.rich_to_str(table, width=512))  # effectively disable per-cell truncation


def _print_tls_dtors(dtors: list[_TlsDtorEntry]) -> None:
    table = Table.grid()
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    decomp_stack_vars = pwndbg.dintegration.manager.get_stack_var_dict_all()
    for dtor in dtors:
        table.add_row(
            f"{pwndbg.color.memory.get(dtor.address)}: ",
            pwndbg.color.memory.get_address_and_symbol(dtor.func, decomp_stack_vars),
            f" \\[obj = {pwndbg.chain.format(dtor.obj)}, map = {pwndbg.color.memory.get(dtor.map)}]",
        )
    print(pwndbg.rich.rich_to_str(table, width=512))


parser = argparse.ArgumentParser(description="List currently registered glibc exit handlers.")


@pwndbg.commands.Command(
    parser, category=pwndbg.commands.CommandCategory.LINUX, aliases=["exitfuncs"]
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "i386", "aarch64", "arm"])
def exithandlers() -> None:
    libc_type = pwndbg.libc.which()
    if libc_type not in {pwndbg.libc.LibcType.GLIBC, pwndbg.libc.LibcType.UNKNOWN}:
        print(f"exithandlers is not implemented for libc type '{libc_type.value}'")
        return

    # Get pointer guard.
    pointer_guard: int | None = _get_pointer_guard()
    if pointer_guard is None:
        print(message.error("Failed to get pointer_guard"))
    else:
        print(f"pointer_guard = {blue(hex(pointer_guard))}")

    # Get exit funcs ptr.
    exit_funcs_ptr: Value | int | None = (
        pwndbg.aglib.symbol.lookup_symbol("__exit_funcs") or _get_exit_funcs_from_emulator()
    )
    initial_struct: int | None = None
    if exit_funcs_ptr is None:
        print(message.error("Failed to get address of __exit_funcs"))
    else:
        print(f"__exit_funcs  @ {pwndbg.color.memory.get(exit_funcs_ptr)}")
        initial_struct = pwndbg.aglib.memory.read_pointer_width(int(exit_funcs_ptr))
        print(f"initial       @ {pwndbg.color.memory.get(initial_struct)}")

    # Get tls dtors ptr.
    tls_dtor_list = (
        pwndbg.aglib.symbol.lookup_symbol("tls_dtor_list") or _get_tls_dtor_list_from_emulator()
    )
    if tls_dtor_list is None:
        print(message.error("Failed to locate tls_dtor_list"))
    else:
        print(f"tls_dtor_list @ {pwndbg.color.memory.get(tls_dtor_list)}")

    # Fetch and print exit funcs if we can.
    print()
    if pointer_guard is not None and initial_struct is not None:
        exit_handlers = _list_exit_handlers(pointer_guard, initial_struct)
        if len(exit_handlers) == 0:
            print("No __exit_funcs handlers registered.")
            return
        print("Registered __exit_funcs handlers:")
        _print_exit_handlers(exit_handlers)

    # Fetch and print tls dtors if we can.
    print()
    if pointer_guard is not None and tls_dtor_list is not None:
        tls_dtors = _list_tls_dtors(pointer_guard, int(tls_dtor_list))
        if len(tls_dtors) == 0:
            print("No tls_dtor handlers registered.")
        else:
            print("Registered tls_dtor handlers:")
            _print_tls_dtors(tls_dtors)
