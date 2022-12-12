import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.lib.kernel.kconfig
import pwndbg.lib.memoize

_kconfig = None


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


@pwndbg.lib.memoize.reset_on_start
def kcmdline() -> str:
    cmdline_addr = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.symbol.address("saved_command_line"))
    return pwndbg.gdblib.memory.string(cmdline_addr).decode("ascii")


@pwndbg.lib.memoize.reset_on_start
def kversion() -> str:
    version_addr = pwndbg.gdblib.symbol.address("linux_banner")
    return pwndbg.gdblib.memory.string(version_addr).decode("ascii").strip()
