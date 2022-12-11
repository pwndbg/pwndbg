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
