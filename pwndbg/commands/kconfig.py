from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Outputs the kernel config.")

parser.add_argument("config_name", nargs="?", type=str, help="A config name to search for")
parser.add_argument("-l", "--load", type=str, dest="file_path", help="load kernel config file")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kconfig(config_name=None, file_path=None) -> None:
    kconfig_ = pwndbg.aglib.kernel.kconfig()
    if file_path is not None:
        kconfig_.update_with_file(file_path)
        return

    if config_name:
        key = kconfig_.get_key(config_name)
        if key:
            val = kconfig_[config_name]
            print(f"{key} = {val}")
        else:
            key = pwndbg.lib.kernel.kconfig.config_to_key(config_name)
            print(f"Config {key} not set")
    else:
        for name, val in kconfig_.items():
            print(f"{name} = {val}")
