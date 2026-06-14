import argparse
import pwndbg.commands
import pwndbg.aglib.symbol
import pwndbg.aglib.memory
import pwndbg.aglib
import pwndbg.aglib.tls
import pwndbg.emu.emulator


def rol(val: int, amount: int) -> int:
    amount %= pwndbg.aglib.arch.ptrbits
    return (
        (val << amount) | val >> (pwndbg.aglib.arch.ptrbits - amount)
    ) & pwndbg.aglib.arch.ptrmask


def ptr_mangle(cookie: int, ptr: int) -> int:
    return rol(ptr ^ cookie, 0x11)


def ptr_demangle(cookie: int, ptr: int) -> int:
    return (rol(ptr, -0x11) ^ cookie) & pwndbg.aglib.arch.ptrmask


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

    string = f"{hex(addr)} [{flavor_str} ({flavor})]"
    if flavor_str in {"ef_on", "ef_cxa", "ef_at", "unknown"}:
        fn_str = pwndbg.aglib.symbol.resolve_addr(fn) or hex(fn)
        string += f": {fn_str}"
    if flavor_str in {"ef_on", "ef_cxa", "unknown"}:
        string += f"({hex(arg)})"
    elif flavor_str == "ef_at":
        string += "(void)"
    if flavor_str in {"ef_cxa", "unknown"}:
        string += f" [dso_handle = {hex(dso_handle)}]"
    return string


parser = argparse.ArgumentParser(description="View glibc exit handlers")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.LINUX)
def exit_handlers() -> None:
    cookie = _get_cookie()
    exit_addr = pwndbg.aglib.symbol.lookup_symbol("exit")
    if exit_addr is None:
        print("Failed to get address of exit")
        return
    emulator = pwndbg.emu.emulator.Emulator()
    emulator.until_call(int(exit_addr))
    exit_funcs_ptr = emulator.read_register("RSI")
    if exit_funcs_ptr is None:
        print("Failed to read RSI")
        return
    exit_function_list = pwndbg.aglib.memory.read_pointer_width(exit_funcs_ptr)
    exit_handlers = []
    while True:
        if exit_function_list == 0:
            break
        num_handlers = pwndbg.aglib.memory.read_pointer_width(
            exit_function_list + pwndbg.aglib.arch.ptrsize
        )
        for i in range(num_handlers):
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
