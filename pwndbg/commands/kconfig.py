from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Outputs the kernel config (requires CONFIG_IKCONFIG)."
)

parser.add_argument("config_name", nargs="?", type=str, help="A config name to search for")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kconfig(config_name=None) -> None:
    kconfig_ = pwndbg.aglib.kernel.kconfig()

    if not kconfig_:
        print(
            M.warn(
                "No kernel configuration found, make sure the kernel was built with CONFIG_IKCONFIG"
            )
        )
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
