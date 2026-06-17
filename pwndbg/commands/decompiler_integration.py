from __future__ import annotations

import argparse
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.symbol
import pwndbg.color.memory as color_mem
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.dintegration
import pwndbg.lib.config
import pwndbg.lib.tempfile
from pwndbg import color
from pwndbg.color import message
from pwndbg.commands import CommandCategory

# ========= Version / Installation code =========

# Bump me if needed.
# (This will trigger check_decomp2dbg_version_bumped())
d2d_required_major, d2d_required_minor, d2d_required_fix = 3, 14, 0

d2d_required_version_str: str = f"{d2d_required_major}.{d2d_required_minor}.{d2d_required_fix}"

d2d_cache_dir: Path = Path(pwndbg.lib.tempfile.cachedir("d2d"))


def decomp2dbg_not_installed_message() -> None:
    print(message.error("decomp2dbg is not installed.\n"))
    print(f"The supported decomp2dbg version is {d2d_required_major}.{d2d_required_minor}.* .")
    print(
        "If you installed Pwndbg with your distribution's package manager, use the same to install decomp2dbg."
    )
    print(
        "(If the version of decomp2dbg in your distro is outdated, complain to them. If our version is outdated, complain to us.)"
    )
    print(
        "If you're using Pwndbg installed from source, run `uv sync --extra decomp2dbg --inexact`."
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
    Checks the version of the decomp2dbg python module.

    Returns True if the version is supported, prints an error message
    and returns False otherwise.
    """
    import decomp2dbg

    ver_arr: list[str] = decomp2dbg.__version__.split(".")
    major: int = int(ver_arr[0])
    minor: int = int(ver_arr[1])
    fix: int = int(ver_arr[2])

    if major == d2d_required_major and (
        (minor > d2d_required_minor) or (minor == d2d_required_minor and fix >= d2d_required_fix)
    ):
        return True

    print(message.system("Unsupported decomp2dbg version installed."))
    msg = f"""
You have version {decomp2dbg.__version__} installed, but we need {d2d_required_version_str}.
This should only be possible if you installed Pwndbg through a package manager. You have a few options, in recommended order:

1. Complain to your distribution's packagers that this version of decomp2dbg is incompatible with this version of Pwndbg.
2. Install Pwndbg any other way: https://pwndbg.re/stable/setup/
3. Install the correct version of decomp2dbg manually.
"""
    print(msg)
    return False


def check_outdated_ghidra_plugin() -> bool:
    """
    Check if the user likely has an outdated version of the ghidra plugin.

    Tell them to update if yes and return False. If everything is up to date return True.

    This should only be checked if (decompiler_host == "localhost").
    """
    version_path: Path = d2d_cache_dir / "ghidra_plugin_version"
    if not version_path.exists():
        # The user has not installed the ghidra plugin yet.
        print(message.error("Ghidra plugin not installed."))
        print(f"(The file {version_path} does not exist)")
        return False

    # Note that we only save the "required version" to this file, because thats the only
    # thing that matters to us.
    version_spec = version_path.read_text().strip()
    if version_spec == d2d_required_version_str:
        # The version is the same i.e. we haven't bumped the required version since the
        # user installed the plugin with `di install ghidra`.
        return True

    # The plugin is outdated.
    print(
        message.error("Ghidra plugin outdated. ")
        + f"You have version {version_spec} but required is {d2d_required_version_str}."
    )
    print("Please run `di install ghidra`.")
    return False


def ghidra_decomp2dbg_version() -> None:
    """
    Save the required decomp2dbg version to a known file.
    """
    version_path: Path = d2d_cache_dir / "version"

    just_in_case: str = version_path.read_text().strip()
    if just_in_case == "fine":
        return

    version_path.write_text(d2d_required_version_str)


def print_d2d_version() -> None:
    import decomp2dbg

    print(f"decomp2dbg version: {decomp2dbg.__version__} (required: {d2d_required_version_str})")


ida_plugin_path = pwndbg.config.add_param(
    "decompiler-ida-plugin-path",
    str(Path.home() / ".idapro/plugins"),
    "where to install the ida integration plugin",
    param_class=pwndbg.lib.config.PARAM_STRING,
)
binja_plugin_path = pwndbg.config.add_param(
    "decompiler-binja-plugin-path",
    str(Path.home() / ".binaryninja/plugins"),
    "where to install the binary ninja integration plugin",
    param_class=pwndbg.lib.config.PARAM_STRING,
)
angr_plugin_path = pwndbg.config.add_param(
    "decompiler-angr-plugin-path",
    str(Path.home() / ".local/share/angr-management/plugins"),
    "where to install the angr integration plugin",
    param_class=pwndbg.lib.config.PARAM_STRING,
)


def install_generic_plugin(
    paths: list[tuple[Path, Path]],
    decomp_name: str,
    packaged_plugin_path: Path,
    config_var: pwndbg.lib.config.Parameter,
):
    """
    Arguments:
        paths: A list of (source path, destination path) tuples. Each element of the list
               will be symlinked (destination) -> (source).
        decomp_name: Pretty name of the decompiler.
        packaged_plugin_path: The path of the folder for the decompiler plugin in the decomp2dbg python package.
        config_var: The variable which holds the destination plugin path.
    """
    print(f"Installing the {decomp_name} decompiler plugin.\n")
    print_d2d_version()

    plugin_destination: Path = Path(str(config_var))

    print("\nSource:      ", packaged_plugin_path)
    print("Destination: ", plugin_destination)

    print("\nMaking sure destination folder exists..\n")
    plugin_destination.mkdir(parents=True, exist_ok=True)

    print("Deleting old files (if they exist):")
    for _, dest in paths:
        print(f"\t{dest}")
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink() or not dest.is_dir():
                # Works for regular files and symlinks.
                # Note that `dest.is_dir()` returns True for
                # symlinks to directories.
                dest.unlink()
            else:
                # This is a non-symlink directory
                shutil.rmtree(str(dest))

    print("\nCreating symlinks:")
    for source, dest in paths:
        print(f"\t{dest} -> {source}")
        dest.symlink_to(source)

    print("\nThe fact that symlinks are used means the decompiler plugin will be automatically")
    print(
        f"updated when the decomp2dbg python package is updated. But {message.notice('if the decomp2dbg')}"
    )
    print(
        f"{message.notice('installation path gets changed')}, don't forget to {message.notice('reinstall')}!"
    )
    print("(so take care if you change the folder of your Pwndbg installation)\n")

    print(
        message.hint(
            f"If you want to change the plugin destination, run `set {config_var.name} the/new/path`.\n"
            "(and put this line into your ~/.gdbinit so you don't have issues in the future)\n"
        )
    )
    print(
        message.success("Installed successfully.")
        + " If your decompiler is already open, restart it. You can use `di connect` now."
    )


def install_ida_plugin() -> None:
    packaged_plugin_path: Path = decomp2dbg_path() / "decompilers/d2d_ida"
    plugin_destination: Path = Path(str(ida_plugin_path))

    packaged1 = packaged_plugin_path / "d2d_ida"
    packaged2 = packaged_plugin_path / "d2d_ida.py"

    dest1 = plugin_destination / "d2d_ida"
    dest2 = plugin_destination / "d2d_ida.py"

    install_generic_plugin(
        [(packaged1, dest1), (packaged2, dest2)], "IDA", packaged_plugin_path, ida_plugin_path
    )


def install_binja_plugin() -> None:
    packaged_plugin_path: Path = decomp2dbg_path() / "decompilers/d2d_binja"

    install_generic_plugin(
        [(packaged_plugin_path, Path(str(binja_plugin_path)) / "d2d_binja")],
        "Binary Ninja",
        packaged_plugin_path,
        binja_plugin_path,
    )


def install_angr_plugin() -> None:
    packaged_plugin_path: Path = decomp2dbg_path() / "decompilers/d2d_angr"

    install_generic_plugin(
        [(packaged_plugin_path, Path(str(angr_plugin_path)) / "d2d_angr")],
        "angr-managment",
        packaged_plugin_path,
        angr_plugin_path,
    )


def install_ghidra_plugin() -> None:
    print("Installing the Ghidra decompiler plugin.")
    print_d2d_version()

    download_url: str = f"https://github.com/mahaloz/decomp2dbg/releases/download/v{d2d_required_version_str}/d2d-ghidra-plugin.zip"
    download_dest: Path = d2d_cache_dir / "d2d-ghidra-plugin.zip"

    print("\nSince the Ghidra extension is written in Java, we download it as already built.")
    print(f"Downloading:\n\t{download_url}\n\t-> {download_dest}")

    try:
        with (
            urllib.request.urlopen(download_url) as response,
            open(str(download_dest), "wb") as out_file,
        ):
            shutil.copyfileobj(response, out_file)
    except urllib.error.HTTPError as e:
        print(message.error("\nHTTP Error while fetching the plugin. Aborting."))
        print("Status code:", e.code)
        print("Reason:", e.reason)
        print("Response body:", e.read())
        return
    except urllib.error.URLError as e:
        print(message.error("\nURL Error while fetching the plugin. Aborting."))
        print("Reason:", e.reason)
        return

    print(message.success("Done.\n"))

    print("Unfortunately, Ghidra doesn't load the plugin instantly on startup, so you ")
    print(
        message.notice("need to tell Ghidra to load the plugin")
        + " by clicking [File > Install Extensions > + (top right)]"
    )
    print(
        "in the Project Managment window. Then restart Ghidra. And in your project you might also need to"
    )
    print(
        "[File > Configure] and enable decomp2dbg decompiler server'. Now you can start the server with "
    )
    print("Ctrl+Shift+D as usual.")

    print(
        message.warn("\nIMPORTANT: ")
        + "Because the Ghidra plugin is not shipped compiled in the decomp2dbg python package, there is no symlink"
    )
    print("and " + message.warn("the plugin will not be automatically updated.\n"))

    version_path: Path = d2d_cache_dir / "ghidra_plugin_version"
    version_path.write_text(d2d_required_version_str)
    print(f"Saved current required version ({d2d_required_version_str}) (to {version_path}).")


def install(which_decompiler: str) -> None:
    if sys.platform == "win32":
        print(
            message.system(
                "Installation on Windows not supported. Install separately: https://github.com/mahaloz/decomp2dbg?tab=readme-ov-file#install ."
            )
        )
        return

    if str(decompiler_host) != "localhost":
        print(message.warn("decompiler-host != localhost: Why are you installing locally then?\n"))
        print("If your decompiler is on another machine, you also need to install the decompiler")
        print("plugin on that machine. Ideally you should do that using `di install` there, but")
        print("if that's not possible (e.g. if you're using Windows there), install the correct")
        print(
            f"version ({d2d_required_version_str}) of decomp2dbg on its own: https://github.com/mahaloz/decomp2dbg?tab=readme-ov-file#install .\n"
        )

        check = input("Are you sure you want to continue [y/N]: ")
        if check.lower() != "y":
            return

        print()

    # If the user is not connecting to localhost, but they decided to continue regardless,
    # then we will still enforce this check.
    if not check_decomp2dbg_version():
        return

    match which_decompiler:
        case "ida":
            install_ida_plugin()
        case "binja":
            install_binja_plugin()
        case "ghidra":
            install_ghidra_plugin()
        case "angr":
            install_angr_plugin()


# ========= End of Version / Installation code =========
# ========= decompiler-integration command handling =========

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


def disconnect() -> None:
    if not pwndbg.dintegration.manager.is_connected():
        print(message.error("Am not connected in the first place."))
        return

    decomp_name = pwndbg.dintegration.manager.decompiler_name()
    pwndbg.dintegration.manager.disconnect()
    print(message.success("Disconnected") + f" from {decomp_name}.")


def connect(also_sync: bool) -> None:
    # Doesn't make sense to check the version this if the local decomp2dbg is not being used.
    if decompiler_host == "localhost" and not check_decomp2dbg_version():
        return

    if pwndbg.dintegration.manager.is_connected():
        print("Reconnecting: ", end="")

    print(f"Connecting to {decompiler_host}:{decompiler_port}.")

    ok = pwndbg.dintegration.manager.connect(str(decompiler_host), int(decompiler_port))
    if ok:
        if decompiler_host != "localhost":
            print(
                "\nConnecting to a remote machine. "
                + message.system("Make sure")
                + " that the version"
            )
            print(
                f"of the decompiler plugin there is {message.system(d2d_required_version_str)}!\n"
            )
        # If we are connected to localhost Ghidra, we need to check that the plugin version is fine.
        elif (
            pwndbg.dintegration.manager.decompiler_id() == pwndbg.dintegration.DecompilerID.GHIDRA
            and not check_outdated_ghidra_plugin()
        ):
            print(message.error("Disconnecting.."))
            pwndbg.dintegration.manager.disconnect()
            return

        decomp_name = pwndbg.dintegration.manager.decompiler_name()
        print(message.success("Connected") + f" to {decomp_name}.")

        if also_sync:
            # In case the binary isn't loaded yet, lets not yell to the user about failing.
            sync(fail_quietly=True)

        return

    print(message.error("Failed connecting."))
    print(message.hint("Did you open the connection in the decompiler? (Ctrl+Shift+D)"))
    print(
        message.hint(
            "(The appropriate decompiler plugin must be installed, see `di install --help`)"
        )
    )


def soft_connection_check(also_sync: bool) -> bool:
    """
    If we are not connected, try to connect (and sync).

    If we were connected, or succeed in connecting, return True,
    otherwise False.
    """
    if not pwndbg.dintegration.manager.is_connected():
        print("Trying to connect.. ", end="")

        connect(also_sync=also_sync)

        # Make sure we were successful.
        if not pwndbg.dintegration.manager.is_connected():
            return False

        # Give space to the actual command output.
        print()

    return True


def check_alive(error_msg: str) -> bool:
    try:
        inf = pwndbg.dbg.selected_inferior()

        if not inf.alive():
            # A bit hacky but whatever.
            raise pwndbg.dbg_mod.NoInferior

        return True
    except pwndbg.dbg_mod.NoInferior:
        print(message.error(error_msg))
        return False


def jump(addr: int | None) -> None:
    if not pwndbg.dintegration.manager.is_connected():
        print(message.error("Not connected to a decompiler."))
        print(message.hint("Try `di connect`."))
        return

    if not check_alive("Can only jump to address while the process is alive."):
        return

    if addr is None:
        if pwndbg.aglib.regs.pc is None:
            print(message.error("Address not specified, and could not find PC."))
            return
        addr = pwndbg.aglib.regs.pc

    ok = pwndbg.dintegration.manager.focus_address(addr)
    if not ok:
        print(message.error("Decompiler failed to jump."))


def sync(fail_quietly: bool) -> None:
    """
    Arguments:
        fail_quietly: If we don't pass the preliminary checks required to perform the sync, don't print anything.
    """
    if fail_quietly:
        # Direct check, no retries.
        if not pwndbg.dintegration.manager.is_connected():
            return

        # Something else is calling us, lets give the output some space.
        print()
    # Noisy check with a connection attempt.
    # Don't try to sync because that sync would be quiet, and we want
    # to complain about errors to the user.
    elif not soft_connection_check(also_sync=False):
        return

    if not check_alive(
        "" if fail_quietly else "Can only sync with the debugger while the process is alive."
    ):
        return

    print("Syncing symbols...")

    # Functions and globals
    nsyms, sym_err = pwndbg.dintegration.manager.update_symbols()
    match sym_err:
        case pwndbg.dintegration.Error.OK:
            if nsyms == 0:
                print("No symbols synced? Something is off. ")
            else:
                print(
                    message.success(f"Synced {nsyms} symbols") + " (globals + functions). ", end=""
                )
        case pwndbg.dintegration.Error.DEBUGGER_NOT_SUPPORTED:
            print("LLDB does not support syncing symbols. ", end="")
        case _:
            print(message.error(f"Failed: {sym_err.value}."))
            if sym_err == pwndbg.dintegration.Error.BINARY_NOT_LOADED:
                print(message.hint("Try `di setpath --help` or `di setbase --help`?"))
            # The error is fundamental to the setup, don't even try to sync function variables.
            return

    # Function-local variables
    nvars, var_err = pwndbg.dintegration.manager.update_function_variables()
    match var_err:
        case pwndbg.dintegration.Error.OK:
            if nvars > 0:
                print(message.success(f"Synced {nvars} variables") + " for the current function.")
            else:
                # It's fine to print this even if fail_quietly=True.
                print("No variables synced for the current function.")
        case pwndbg.dintegration.Error.NO_FRAME:
            # It's fine to print this even if fail_quietly=True.
            print("No variables synced for the current function (no stack frame found).")
        case pwndbg.dintegration.Error.NO_CONNECTION:
            print(message.error(f"Failed: {sym_err.value}."))


def list_one_frame(frame: pwndbg.dbg_mod.Frame, idx: int | None = None) -> None:
    func_vars: pwndbg.dintegration.RebasedFuncVariables | None = (
        pwndbg.dintegration.manager.get_function_vars_rebased_from_frame(frame)
    )

    pc: int = frame.pc()
    sp: int = frame.sp()
    start: int | None = frame.start()

    symbol: str | None = pwndbg.aglib.symbol.resolve_addr(pc)
    if symbol:
        symbol_text = color.blue(symbol)
    else:
        symbol_text = "???"

    if idx is not None:
        frame_text = f"#{idx} {symbol_text} frame:"
    else:
        frame_text = f"{symbol_text} frame:"

    pc_text = color.blue(hex(pc))
    sp_text = color_mem.get(sp)
    start_text = color_mem.get(start) if start is not None else "???"
    padding = " " * 4

    print(frame_text)
    print(f"{padding}@ {pc_text}")
    print(f"{padding}{sp_text} -> {start_text}")

    if func_vars is None:
        # Common reason is that we are in a function in a different binary.
        print("Could not get function variables from decompiler.")
        return

    if len(func_vars.reg_vars) == 0:
        print("No register variables.")
    else:
        print("Register variables:")

        for reg_var in func_vars.reg_vars:
            name_text = color.green(color.bold(reg_var.name))
            type_text = color.light_cyan(reg_var.type)
            reg_text = reg_var.reg_name.ljust(4, " ")
            # FIXME: Should probably refactor this to use pwndbg.commands.context.get_regs (but then also
            # refactor that, to pull it out of pwndbg/commands, maybe separate out register name and value etc.)
            reg_value_raw: pwndbg.dbg_mod.Value | None = frame.regs().by_name(reg_var.reg_name)
            try:
                reg_value = (
                    color_mem.get(int(reg_value_raw))
                    if reg_value_raw is not None
                    else color.gray("???")
                )
            except pwndbg.dbg_mod.Error:
                # int(reg_value_raw) failed. Happens for xmm0 for instance.
                reg_value = "not an int"
            reg_value_part = color.ljust_colored(f"(value: {reg_value})", 28)
            print(f"{reg_text} {reg_value_part} <- {name_text} (type: {type_text})")

    if len(func_vars.stack_vars) == 0:
        print("No stack variables.")
    else:
        print("Stack variables:")

        for stack_var in func_vars.stack_vars:
            name_text = color.green(color.bold(stack_var.name))
            type_text = color.light_cyan(stack_var.type)
            addr_text = color.ljust_colored(color_mem.get(stack_var.addr), 18)
            from_sp = stack_var.addr - sp
            from_sp_text = f"[sp + {from_sp:#x}]"
            if start:
                from_frame = start - stack_var.addr
                from_frame_text = f"[frame - {from_frame:#x}]"
            else:
                from_frame_text = "[???]"

            print(
                f"{addr_text} <- {name_text} (type: {type_text}) {from_sp_text} {from_frame_text}"
            )


def list_all_frames() -> None:
    thread = pwndbg.dbg.selected_thread()
    if thread is None:
        print(message.error("Could not find current thread."))
        return

    idx = 0
    with thread.bottom_frame() as bottom_frame:
        cur_frame = bottom_frame
        # Crawl up the stack
        while cur_frame is not None:
            list_one_frame(cur_frame, idx)
            print("==================")
            cur_frame = cur_frame.parent()
            idx += 1


def list_(list_all: bool) -> None:
    if not soft_connection_check(also_sync=True):
        return

    if not check_alive("Can only list function variables if the process is alive."):
        return

    if list_all:
        list_all_frames()
    else:
        frame: pwndbg.dbg_mod.Frame | None = pwndbg.dbg.selected_frame()
        if frame is None:
            print(message.error("Could not find current stack frame."))
            return
        list_one_frame(frame)


def setpath(path: str) -> None:
    # I make this a command instead of a config for consistency with setbase.

    # Unset manual base first
    if pwndbg.dintegration.manual_binary_address != -1:
        print(
            f"Unset the previously set `di setbase` value of {pwndbg.dintegration.manual_binary_address}."
        )
        pwndbg.dintegration.manual_binary_address = -1

    pwndbg.dintegration.manual_binary_path = path
    print(f'Path of the decompiled binary in the address space set to "{path}".')
    if path == "":
        print("(back to automatic detection)")

    if pwndbg.dintegration.manager.is_connected():
        print("Reconnecting to apply changes..\n")
        connect(also_sync=True)


def setbase(base_addr: int) -> None:
    # I use a command like this instead of a config parameter because it seems
    # GDB doesn't allow values > 2^32.
    if base_addr < -1:
        print(message.error("Valid values are in [-1, 2^64)."))
        return

    # Unset manual path first
    if pwndbg.dintegration.manual_binary_path != "":
        print(
            f"Unset the previously set `di setpath` value of {pwndbg.dintegration.manual_binary_path}."
        )
        pwndbg.dintegration.manual_binary_path = ""

    pwndbg.dintegration.manual_binary_address = base_addr
    print(f"Base address of the decompiled binary set to {base_addr:#x}.")
    if base_addr == -1:
        print("(back to automatic detection)")

    if pwndbg.dintegration.manager.is_connected():
        print("Reconnecting to apply changes..\n")
        connect(also_sync=True)


parser = argparse.ArgumentParser(
    description="""Control Pwndbg decompiler integration.

See https://pwndbg.re/dev/tutorials/decompiler-integration/ for usage instructions."""
)
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True

parser_connect = subparsers.add_parser(
    "connect",
    aliases=["c"],
    help="Connect to the decompiler",
    description="""
Connect to the decompiler.

The host and port to connect to are governed by the `decompiler-host`
and `decompiler-port` config variables. Try `help set decompiler-host`.
""",
)

parser_disconnect = subparsers.add_parser(
    "disconnect",
    aliases=["d"],
    help="Disconnect from the decompiler",
    description="Disconnect from the decompiler.",
)

parser_sync = subparsers.add_parser(
    "sync",
    aliases=["s"],
    help="Sync data from the decompiler",
    description="""
Sync data from the decompiler.

Check out `help set decompiler-autosync-syms` and `help set decompiler-autosync-vars`.
""",
)

parser_jump = subparsers.add_parser(
    "jump",
    aliases=["j"],
    help="Make the decompiler's cursor jump to the PC",
    description="""
Make the decompiler's cursor jump to the PC.

Check out `help set decompiler-autojump`.
""",
)
parser_jump.add_argument(
    "jump_addr",
    metavar="addr",
    type=int,
    nargs="?",
    default=None,
    help="Address to jump to. (default: pc)",
)

parser_install = subparsers.add_parser(
    "install",
    help="Install the decompiler plugins",
    description="""
Install/update the decompiler plugins.

You need a decompiler plugin installed to allow the decompiler to communicate
back to Pwndbg. The decompiler plugins are from decomp2dbg (<3).

If you already have decomp2dbg installed, this command will overwrite
that installation in order to pin the proper version that Pwndbg needs. You will
still be able to use decomp2dbg outside of Pwndbg.

You should take care not to invoke `source /path/to/decomp2dbg/d2d.py` in your ~/.gdbinit
because we implement the debugger-side logic independently, and it might conflict.
""",
)
install_subparsers = parser_install.add_subparsers(dest="install_sub", metavar="which")
install_subparsers.required = True

parser_install_ida = install_subparsers.add_parser(
    "ida",
    help="Install the IDA decompiler plugin",
    description="Install the IDA decompiler plugin.",
)
parser_install_binja = install_subparsers.add_parser(
    "binja",
    help="Install the Binary Ninja decompiler plugin",
    description="Install the Binary Ninja decompiler plugin.",
)
parser_install_ghidra = install_subparsers.add_parser(
    "ghidra",
    help="Install the Ghidra decompiler plugin",
    description="Install the Ghidra decompiler plugin.",
)
parser_install_angr = install_subparsers.add_parser(
    "angr",
    help="Install the angr-management decompiler plugin",
    description="Install the angr-managment decompiler plugin.",
)

parser_decomp = subparsers.add_parser(
    "decomp",
    help="Just use the `decomp` command",
    description="Just use the `decomp` command.",
)

parser_list = subparsers.add_parser(
    "list",
    aliases=["l"],
    help="List the variables for the current stack frame",
    description="""
List the variables for the current stack frame.

Will not be accurate in a function's prologue (before the stack pointer has been adjusted).
The "frame" for the purposes of this command is (usually) the location of the saved return address.
""",
)
parser_list.add_argument(
    "-a",
    "--all",
    help="List decompiler stack variables from all stack frames in this thread.",
    action="store_true",
    default=False,
    dest="list_all",
)

parser_set_base = subparsers.add_parser(
    "setbase",
    help="Manually set the base memory address of the decompiled binary",
    description="""
Manually set the base memory address of the decompiled binary.

Normally, Pwndbg will use the file path that the decompiler reports for the binary and
check it against all files mapped into memory to find the correct base address.

If for some reason the file names differ or your binary does not show up in the memory
mappings, you can manually set the base address using this command. This is commonly
needed when debugging a kernel module.

If you wish to re-enable automatic base address detection, set this value to -1 (or
restart Pwndbg).

Setting this automatically unsets the `di setpath` value.
""",
)
parser_set_base.add_argument(
    "binary_addr",
    metavar="addr",
    type=int,
    help="Memory address of the decompiled binary in the address space",
)

parser_set_path = subparsers.add_parser(
    "setpath",
    help="Manually set the path of the binary as loaded in memory",
    description="""
Manually set the path of the binary as loaded in memory.

Normally, Pwndbg will use the file path that the decompiler reports for the binary and
check it against all files mapped into memory to find the correct base address.

If for some reason the file names differ or your binary does not show up in the memory
mappings, you can manually specify the actual path of the binary as loaded in memory (
the one reported by /proc/<pid>/maps i.e. vmmap).

If you wish to re-enable automatic base address detection, set this value to "" (or
restart Pwndbg).

Setting this automatically unsets the `di setbase` value.
""",
)
parser_set_path.add_argument(
    "binary_path",
    metavar="path",
    type=str,
    help="File path of the decompiled binary as loaded in memory",
)


@pwndbg.commands.Command(
    parser, aliases=["di"], category=pwndbg.commands.CommandCategory.INTEGRATIONS
)
def decompiler_integration(
    command: str,
    jump_addr: int | None = None,
    install_sub: str = "",
    list_all: bool = False,
    binary_addr: int = -1,
    binary_path: str = "",
) -> None:
    # decomp2dbg is an optional dependancy for now, so we check for it.
    try:
        match command:
            case "connect" | "c":
                connect(also_sync=True)
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
            case "list" | "l":
                list_(list_all)
            case "setbase":
                setbase(binary_addr)
            case "setpath":
                setpath(binary_path)
    except ModuleNotFoundError as e:
        if e.name != "decomp2dbg":
            raise e
        decomp2dbg_not_installed_message()


# ========= End of decompiler-integration command handling =========
# ========= Automatic integration handling =========

should_autosync_syms = pwndbg.config.add_param(
    "decompiler-autosync-syms",
    False,
    "whether to sync symbols with the decompiler on every stop",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
    help_docstring="""
Depending on the decompiler, the number of symbols (functions + global variables)
the binary you are decompiling has, and various other factors, this may or may not
be a good idea. Try it out and see.

Check out the other decompiler-auto* configuration variables as well.
""",
)

should_autosync_vars = pwndbg.config.add_param(
    "decompiler-autosync-vars",
    True,
    "whether to sync function variables with the decompiler on every stop",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
    help_docstring="""
This is generally lightweight, so it is enabled by default. Try disabling
it if you have performance issues.

Check out the other decompiler-auto* configuration variables as well.
""",
)

should_autojump = pwndbg.config.add_param(
    "decompiler-autojump",
    False,
    "whether to jump the decompiler cursor on every stop",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
    help_docstring="""
Depending on the decompiler, this may or may not be a good idea.
Try it out and see.

Check out the other decompiler-auto* configuration variables as well.
""",
)


def auto_jump():
    if pwndbg.aglib.regs.pc is None:
        return
    addr: int = pwndbg.aglib.regs.pc

    pwndbg.dintegration.manager.focus_address(addr)


@pwndbg.dbg.event_handler(pwndbg.dbg_mod.EventType.STOP)
def automatic_operations() -> None:
    # The connection and inf.alive() checks in sync() are just for better error
    # reporting, the manager will handle them anyway.

    # We succeed quietly to not mess up the `context-reserve-lines` logic.

    if should_autosync_syms:
        pwndbg.dintegration.manager.update_symbols()

    if should_autosync_vars:
        pwndbg.dintegration.manager.update_function_variables()

    if should_autojump:
        auto_jump()


# ========= End of Automatic integration handling =========
# ========= The decomp command =========

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
    # Same as the default for context-code-lines
    default=14,
    help="Number of lines of decompilation to show.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.INTEGRATIONS)
@pwndbg.commands.OnlyWhenRunning
def decomp(addr: int | None, lines: int) -> None:
    if addr is None:
        if pwndbg.aglib.regs.pc is None:
            print("Address not specified, and could not find PC.")
            return
        addr = pwndbg.aglib.regs.pc

    if not soft_connection_check(also_sync=True):
        return

    decomp = pwndbg.dintegration.manager.decompile_pretty(addr, lines)

    if decomp is None:
        print("Could not retrieve decompilation.")
    else:
        print("\n".join(decomp))
