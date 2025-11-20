from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Optional

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.regs
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.integration
import pwndbg.lib.config
from pwndbg.commands import CommandCategory

# Bump me if needed.
d2d_required_major = 3
d2d_required_minor = 12
d2d_required_fix = 0


decompiler_host = pwndbg.config.add_param(
    "decompiler-host",
    "localhost",
    "the host where the decompiler is exposed",
    param_class=pwndbg.lib.config.PARAM_STRING,
)

decompiler_port = pwndbg.config.add_param(
    "decompiler-port",
    3662,
    "the port on which the decompiler is exposed",
    param_class=pwndbg.lib.config.PARAM_UINTEGER,
)


def decomp2dbg_path() -> Path:
    """
    Returns the absolute path to the directory where decomp2dbg is installed.

    If Pwndbg is installed from source this will be
    /path/to/pwndbg/.venv/lib/python3.13/site-packages/decomp2dbg.
    """
    import decomp2dbg

    return Path(decomp2dbg.__file__).parent.resolve()


def check_decomp2dbg_version() -> bool:
    """
    Returns True if the version is supported, prints an error message
    and returns False otherwise.
    """
    import decomp2dbg

    ver_arr: list[str] = decomp2dbg.__version__.split(".")
    major: int = int(ver_arr[0])
    minor: int = int(ver_arr[1])
    fix: int = int(ver_arr[2])


    if major == d2d_required_major and ((minor > d2d_required_minor) or (minor == d2d_required_minor and fix >= d2d_required_fix)):
        return True

    print(message.system("Unsupported decomp2dbg version installed."))
    msg = f"""
You have version {decomp2dbg.__version__} installed, but we need {d2d_required_major}.{d2d_required_minor}.{d2d_required_fix}.
This should only be possible if you installed Pwndbg through a package manager. You have a few options, in recommended order:

1. Complain to your distribution's packagers that this version of decomp2dbg is incompatible with this version of Pwndbg.
2. Install Pwndbg any other way: https://pwndbg.re/stable/setup/
3. Install the correct version of decomp2dbg manually.
"""
    print(msg)
    return False

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


def install_ida_plugin():
    pass

def install_binja_plugin():
    pass

def install_ghidra_plugin():
    pass

def install_angr_plugin():
    pass


def install(which_decompiler: str):
    if not check_decomp2dbg_version():
        return

    match which_decompiler:
        case "ida":
            install_ida_plugin()
        case "binja":
            install_binja_plugin()
        case "ghidra":
            install_ghidra_plugin()
        case "angr-managment":
            install_angr_plugin()


def jump(addr: Optional[int]):
    if not pwndbg.integration.manager.is_connected():
        print(message.error("Not connected to a decompiler."))
        print(message.hint("Try `di connect`."))
        return

    # Check if the process is alive
    if (inf := pwndbg.dbg.selected_inferior()) is None or not inf.alive():
        print(message.error("Can only jump to address while the process is alive."))
        return

    if addr is None:
        if pwndbg.aglib.regs.pc is None:
            print(message.error("Address not specified, and could not find PC."))
            return
        addr = pwndbg.aglib.regs.pc

    ok = pwndbg.integration.manager.focus_address(addr)
    if not ok:
        print(message.error("Decompiler failed to jump."))


def sync(fail_quietly: bool):
    if not pwndbg.integration.manager.is_connected():
        if not fail_quietly:
            print(message.error("Not connected to a decompiler."))
            print(message.hint("Try `di connect`."))
        return

    # Check if the process is alive
    if (inf := pwndbg.dbg.selected_inferior()) is None or not inf.alive():
        if not fail_quietly:
            print(message.notice("Can only sync with the debugger while the process is alive."))
        return

    # Functions and globals
    nsyms = pwndbg.integration.manager.update_symbols()
    print(message.success(f"Synced {nsyms} symbols") + " (globals + functions).")

    # Function-local variables
    if pwndbg.aglib.regs.pc is not None:
        nvars = pwndbg.integration.manager.update_function_variables(pwndbg.aglib.regs.pc)
        print(message.success(f"Synced {nvars} variables") + " for the current function.")
    else:
        print(message.error("Could not find PC for syncing function-local variables."))


def list_():
    assert 0


def disconnect():
    if not pwndbg.integration.manager.is_connected():
        print(message.error("Am not connected in the first place."))
        return

    decompid = pwndbg.integration.manager.decompiler_id()
    decomp_name = "???"
    if decompid:
        decomp_name = decompid.value

    pwndbg.integration.manager.disconnect()
    print(message.success("Disconnected") + f" from {decomp_name}.")


def connect():
    if not check_decomp2dbg_version():
        return

    if pwndbg.integration.manager.is_connected():
        print("Reconnecting..")

    ok = pwndbg.integration.manager.connect(str(decompiler_host), int(decompiler_port))
    if ok:
        decompid = pwndbg.integration.manager.decompiler_id()
        # This branch should practically always be taken.
        if decompid:
            decomp_name = decompid.value
            print(
                message.success("Connected")
                + f" to {decomp_name} on {str(decompiler_host)}:{int(decompiler_port)}."
            )

            # Surely we always want to sync as soon as we connect.
            # But in case the binary isn't loaded yet, lets not yell to the user about failing.
            sync(fail_quietly=True)
            return

    print(message.error("Failed connecting."))
    print(message.hint("Did you open the connection in the decompiler? (Ctrl+Shift+D)"))
    print(
        message.hint(
            "(The appropriate decompiler plugin must be installed, see `di install --help`)"
        )
    )


parser = argparse.ArgumentParser(description="Control Pwndbg decompiler integration.")
subparsers = parser.add_subparsers(dest="command")

if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
    subparsers.required = True

parser_connect = subparsers.add_parser(
    "connect",
    prog="di connect",
    aliases=["c"],
    help="Connect to the decompiler",
    description="""
Connect to the decompiler.

The host and port to connect to are governed by the `decompiler-host`
and `decompiler-port` config variables. Try `help set decompiler-host`.
""",
    # FIXME: ^^ why aren't newlines respected?
)

parser_disconnect = subparsers.add_parser(
    "disconnect",
    prog="di disconnect",
    aliases=["d"],
    help="Disconnect from the decompiler",
    description="Disconnect from the decompiler.",
)

parser_sync = subparsers.add_parser(
    "sync",
    prog="di sync",
    aliases=["s"],
    help="Sync data from the decompiler",
    description="Sync data from the decompiler",
)

parser_jump = subparsers.add_parser(
    "jump",
    prog="di jump",
    aliases=["j"],
    help="Make the decompiler's cursor jump to the PC",
    description="Make the decompiler's cursor jump to the PC.",
)
parser_jump.add_argument(
    "jump_addr",
    metavar="addr",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address to jump to. (default: pc)",
)

parser_install = subparsers.add_parser(
    "install",
    prog="di install",
    help="Install the decompiler plugins",
    description="""
Install the decompiler plugins.

You need a decompiler plugin installed to allow the decompiler to communicate
back to Pwndbg. The decompiler plugins are from decomp2dbg (<3).

If you already have decomp2dbg installed, this command will overwrite
that installation in order to pin the proper version that Pwndbg needs. You will
still be able to use decomp2dbg outside of Pwndbg.

You should take care not to invoke `source /path/to/decomp2dbg/d2d.py` in your ~/.gdbinit
because we implement the debugger-side logic independently, and it might conflict.
""",
)
install_subparsers = parser_install.add_subparsers(
    dest="install_sub",
    metavar="which"
)
parser_install_ida = install_subparsers.add_parser(
    "ida",
    prog="di install ida",
    help="Install the IDA decompiler plugin",
    description="Install the IDA decompiler plugin."
)
parser_install_binja = install_subparsers.add_parser(
    "binja",
    prog="di install binja",
    help="Install the Binary Ninja decompiler plugin",
    description="Install the Binary Ninja decompiler plugin."
)
parser_install_ghidra = install_subparsers.add_parser(
    "ghidra",
    prog="di install ghidra",
    help="Install the Ghidra decompiler plugin",
    description="Install the Ghidra decompiler plugin."
)
parser_install_angr = install_subparsers.add_parser(
    "angr",
    prog="di install angr",
    help="Install the angr-management decompiler plugin",
    description="Install the angr-managment decompiler plugin."
)

parser_decomp = subparsers.add_parser(
    "decomp",
    prog="di decomp",
    help="Just use the `decomp` command",
    description="Just use the `decomp` command.",
)

parser_list = subparsers.add_parser(
    "list",
    prog="di list",
    aliases=["l"],
    help="List the variables for the current stack frame",
    description="List the variables for the current stack frame.",
)
# FIXME: ^^ add flag -a for all stack frames


@pwndbg.commands.Command(
    parser, aliases=["di"], category=pwndbg.commands.CommandCategory.INTEGRATIONS
)
def decompiler_integration(command: str, jump_addr: Optional[int] = None, install_sub: str = ""):
    match command:
        case "connect" | "c":
            connect()
        case "disconnect" | "d":
            disconnect()
        case "sync" | "s":
            sync(fail_quietly=False)
        case "jump" | "j":
            jump(jump_addr)
        case "install":
            install(install_sub)
        case "decomp":
            print(message.notice("Just use the `decomp` command."))
        case "list":
            list_()


parser = argparse.ArgumentParser(
    description="Use the current integration to decompile code near an address."
)

parser.add_argument(
    "addr",
    type=int,
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
