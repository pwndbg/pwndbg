from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.regs
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.integration
from typing import Optional
from pwndbg.commands import CommandCategory


def decomp2dbg_path() -> Path:
    """
    Returns the absolute path to the directory where decomp2dbg is installed.

    If Pwndbg is installed from source this will be
    /path/to/pwndbg/.venv/lib/python3.13/site-packages/decomp2dbg.
    """
    import decomp2dbg

    return Path(decomp2dbg.__file__).parent.resolve()


parser = argparse.ArgumentParser(description="Install/update the Ida integration plugin.")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.INTEGRATIONS)
def install_ida_integration() -> None:
    ida_plugin_path: Path = decomp2dbg_path() / "decompilers/d2d_ida"
    ida_plugin_destination: Path = Path.home() / ".idapro/plugins/"

    # Ensure it exists
    ida_plugin_destination.mkdir(parents=True, exist_ok=True)

    # symlink would be better but whatever
    print(f"Copying contents of\n {ida_plugin_path}\ninto\n {ida_plugin_destination}")
    shutil.copytree(ida_plugin_path, ida_plugin_destination, dirs_exist_ok=True)


parser = argparse.ArgumentParser(description="Install/update the Binary Ninja integration plugin.")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.INTEGRATIONS)
def install_binja_integration() -> None:
    binja_plugin_path: Path = decomp2dbg_path() / "decompilers/d2d_binja"
    binja_plugin_destination: Path = Path.home() / ".binaryninja/plugins/d2d_binja"

    # Ensure it exists
    binja_plugin_destination.mkdir(parents=True, exist_ok=True)

    # symlink would be better but whatever
    print(f"Copying\n {binja_plugin_path}\nto\n {binja_plugin_destination}")
    shutil.copytree(binja_plugin_path, binja_plugin_destination, dirs_exist_ok=True)


@pwndbg.commands.Command(
    "Sync with the decompiler stuff", category=pwndbg.commands.CommandCategory.INTEGRATIONS
)
def dc_sync():
    pwndbg.integration.manager.update_symbols()
    if pwndbg.aglib.regs.pc is not None:
        pwndbg.integration.manager.update_function_variables(pwndbg.aglib.regs.pc)


@pwndbg.commands.Command(
    "Connect to the decompiler", category=pwndbg.commands.CommandCategory.INTEGRATIONS
)
def dc_connect() -> None:
    ok = pwndbg.integration.manager.connect("localhost", 3662)
    if ok:
        dc_sync()
        print(message.success("Connected!"))
    else:
        print(message.success("Failed connecting"))


parser = argparse.ArgumentParser(
    description="Jump to address in the decompiler"
)

parser.add_argument(
    "addr",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address to jump to. (default: pc)",
)

@pwndbg.commands.Command(
    parser, category=pwndbg.commands.CommandCategory.INTEGRATIONS
)
def dc_jump(addr: Optional[int]) -> None:
    if addr is None:
        if pwndbg.aglib.regs.pc is None:
            print("Address not specified, and could not find PC.")
            return
        addr = pwndbg.aglib.regs.pc

    ok = pwndbg.integration.manager.focus_address(addr)
    if not ok:
        print("Decompiler failed to jump.")


parser = argparse.ArgumentParser(
    description="Use the current integration to decompile code near an address."
)

parser.add_argument(
    "addr",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address to decompile near. (default: pc)",
)
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=10,
    help="Number of lines of decompilation to show.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.INTEGRATIONS)
@pwndbg.commands.OnlyWhenRunning
def decomp(addr: Optional[int], lines: int) -> None:
    if addr is None:
        if pwndbg.aglib.regs.pc is None:
            print("Address not specified, and could not find PC.")
            return
        addr = pwndbg.aglib.regs.pc

    decomp = pwndbg.integration.manager.decompile_pretty(addr, lines)

    if decomp is None:
        print("Could not retrieve decompilation.")
    else:
        print("\n".join(decomp))
