from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.tls
import pwndbg.color.memory
import pwndbg.color.message
import pwndbg.commands
import pwndbg.dintegration
import pwndbg.emu.emulator


def rol(val: int, amount: int) -> int:
    amount %= pwndbg.aglib.arch.ptrbits
    return (
        (val << amount) | val >> (pwndbg.aglib.arch.ptrbits - amount)
    ) & pwndbg.aglib.arch.ptrmask


def ptr_mangle(cookie: int, ptr: int) -> int:
    return rol(ptr ^ cookie, pwndbg.aglib.arch.ptrsize * 2 + 1)


def ptr_demangle(cookie: int, ptr: int) -> int:
    return (rol(ptr, -(pwndbg.aglib.arch.ptrsize * 2 + 1)) ^ cookie) & pwndbg.aglib.arch.ptrmask


def _get_cookie() -> int:
    tls_addr = (
        pwndbg.aglib.tls.find_address_with_register()
        or pwndbg.aglib.tls.find_address_with_pthread_self()
    )
    return pwndbg.aglib.memory.read_pointer_width(tls_addr + pwndbg.aglib.arch.ptrsize * 6)


def _exit_function_to_string(addr: int, flavor: int, fn: int, arg: int, dso_handle: int) -> str:
    match flavor:
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

    string = f"{pwndbg.color.memory.get(addr)} [{flavor_str} ({flavor})]"
    if flavor_str in {"ef_on", "ef_cxa", "ef_at", "unknown"}:
        decomp_stack_vars = pwndbg.dintegration.manager.get_stack_var_dict_all()
        fn_str = pwndbg.color.memory.get_address_and_symbol(fn, decomp_stack_vars)
        string += f": {fn_str}"
    if flavor_str in {"ef_on", "ef_cxa", "unknown"}:
        string += f" [arg = {pwndbg.color.memory.get(arg)}"
    if flavor_str in {"ef_cxa", "unknown"}:
        string += f", dso_handle = {pwndbg.color.memory.get(dso_handle)}]"
    return string


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
        exit_funcs_ptr = int.from_bytes(exit_funcs_ptr_bytes, "little")

    else:
        emulator.until_jump(int(exit_addr))
        abi = pwndbg.aglib.arch.function_abi
        if abi is None:
            print(pwndbg.color.message.error("arch.function_abi is None"))
            return None
        exit_funcs_ptr = emulator.read_register(abi.register_arguments[1])
        if exit_funcs_ptr is None:
            print(pwndbg.color.message.error("Failed to read RSI register"))
            return None
    return exit_funcs_ptr


parser = argparse.ArgumentParser(description="View glibc exit handlers")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.LINUX)
def exit_handlers() -> None:
    cookie = _get_cookie()
    print(f"PTR_MANGLE cookie: {pwndbg.color.message.notice(hex(cookie))}")
    exit_funcs_ptr = (
        pwndbg.aglib.symbol.lookup_symbol("__exit_funcs") or _get_exit_funcs_from_emulator()
    )
    if exit_funcs_ptr is None:
        print(pwndbg.color.message.error("Failed to get address of __exit_funcs"))
        return
    exit_funcs_ptr = int(exit_funcs_ptr)
    exit_function_list = pwndbg.aglib.memory.read_pointer_width(exit_funcs_ptr)
    print(f"Registered handlers (__exit_funcs @ {pwndbg.color.memory.get(exit_function_list)}):")
    exit_handlers = []
    while True:
        if exit_function_list == 0:
            break
        num_handlers = pwndbg.aglib.memory.read_pointer_width(
            exit_function_list + pwndbg.aglib.arch.ptrsize
        )
        for i in range(num_handlers)[::-1]:
            struct_base = exit_function_list + pwndbg.aglib.arch.ptrsize * (2 + 4 * i)
            flavor = pwndbg.aglib.memory.read_pointer_width(struct_base)
            fn = ptr_demangle(
                cookie,
                pwndbg.aglib.memory.read_pointer_width(struct_base + pwndbg.aglib.arch.ptrsize),
            )
            arg = pwndbg.aglib.memory.read_pointer_width(
                struct_base + pwndbg.aglib.arch.ptrsize * 2
            )
            dso_handle = pwndbg.aglib.memory.read_pointer_width(
                struct_base + pwndbg.aglib.arch.ptrsize * 3
            )
            exit_handlers.append((struct_base, flavor, fn, arg, dso_handle))
        exit_function_list = pwndbg.aglib.memory.read_pointer_width(exit_function_list)

    for func in exit_handlers:
        print(_exit_function_to_string(*func))
