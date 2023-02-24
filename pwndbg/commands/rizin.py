import argparse
import subprocess

import pwndbg.commands
import pwndbg.rizin
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Launches rizin.", epilog="Example: rz -- -S -AA")
parser.add_argument("--no-seek", action="store_true", help="Do not seek to current pc")
parser.add_argument(
    "--no-rebase",
    action="store_true",
    help="Do not set the base address for PIE according to the current mapping",
)
parser.add_argument("arguments", nargs="*", type=str, help="Arguments to pass to rizin")


@pwndbg.commands.ArgparsedCommand(parser, aliases=["rizin"], category=CommandCategory.INTEGRATIONS)
@pwndbg.commands.OnlyWithFile
def rz(arguments, no_seek=False, no_rebase=False) -> None:
    filename = pwndbg.gdblib.file.get_proc_exe_file()

    # Build up the command line to run
    cmd = ["rizin"]
    flags = ["-e", "io.cache=true"]
    if pwndbg.gdblib.proc.alive:
        addr = pwndbg.gdblib.regs.pc
        if pwndbg.gdblib.elf.get_elf_info(filename).is_pie:
            if no_rebase:
                addr -= pwndbg.gdblib.elf.exe().address
            else:
                flags.extend(["-B", hex(pwndbg.gdblib.elf.exe().address)])
        if not no_seek:
            cmd.extend(["-s", hex(addr)])
    cmd.extend(flags)
    cmd += arguments
    cmd.extend([filename])

    try:
        subprocess.call(cmd)
    except Exception:
        print("Could not run rizin. Please ensure it's installed and in $PATH.")


parser = argparse.ArgumentParser(
    description="Execute stateful rizin commands through rzpipe.",
    epilog="Example: rzpipe pdf sym.main",
)
parser.add_argument("arguments", nargs="+", type=str, help="Arguments to pass to rzpipe")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.INTEGRATIONS)
@pwndbg.commands.OnlyWithFile
def rzpipe(arguments) -> None:
    try:
        rz = pwndbg.rizin.rzpipe()
        print(rz.cmd(" ".join(arguments)))
    except ImportError:
        print(message.error("Could not import rzpipe python library"))
    except Exception as e:
        print(message.error(e))
