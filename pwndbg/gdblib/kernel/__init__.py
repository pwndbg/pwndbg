import functools

import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.lib.kernel.kconfig
import pwndbg.lib.memoize

_kconfig = None


@pwndbg.lib.memoize.reset_on_objfile
def has_debug_syms() -> bool:
    # Check for an arbitrary type and symbol name that are not likely to change
    return (
        pwndbg.gdblib.typeinfo.load("struct file") is not None
        and pwndbg.gdblib.symbol.address("linux_banner") is not None
    )


def requires_debug_syms(default=None):
    def decorator(f):
        @functools.wraps(f)
        def func(*args, **kwargs):
            if has_debug_syms():
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when debug symbols are
            # not available, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(f"Function {f.__name__} requires CONFIG_IKCONFIG")

        return func

    return decorator


@requires_debug_syms(default={})
def load_kconfig():
    config_start = pwndbg.gdblib.symbol.address("kernel_config_data")
    config_end = pwndbg.gdblib.symbol.address("kernel_config_data_end")
    config_size = config_end - config_start

    compressed_config = pwndbg.gdblib.memory.read(config_start, config_size)
    return pwndbg.lib.kernel.kconfig.Kconfig(compressed_config)


@pwndbg.lib.memoize.reset_on_start
def kconfig():
    global _kconfig
    if _kconfig is None:
        _kconfig = load_kconfig()
    return _kconfig


@requires_debug_syms(default="")
@pwndbg.lib.memoize.reset_on_start
def kcmdline() -> str:
    cmdline_addr = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.symbol.address("saved_command_line"))
    return pwndbg.gdblib.memory.string(cmdline_addr).decode("ascii")


@requires_debug_syms(default="")
@pwndbg.lib.memoize.reset_on_start
def kversion() -> str:
    version_addr = pwndbg.gdblib.symbol.address("linux_banner")
    return pwndbg.gdblib.memory.string(version_addr).decode("ascii").strip()


@requires_debug_syms()
@pwndbg.lib.memoize.reset_on_start
def is_kaslr_enabled() -> bool:
    if "CONFIG_RANDOMIZE_BASE" not in kconfig():
        return False

    return "nokaslr" not in kcmdline()
