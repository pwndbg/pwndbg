import argparse
import subprocess

import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.radare2

parser = argparse.ArgumentParser(description="Launches radare2", epilog="Example: r2 -- -S -AA")
parser.add_argument("--no-seek", action="store_true", help="Do not seek to current pc")
parser.add_argument(
    "--no-rebase",
    action="store_true",
    help="Do not set the base address for PIE according to the current mapping",
)
parser.add_argument("arguments", nargs="*", type=str, help="Arguments to pass to radare")


@pwndbg.commands.ArgparsedCommand(parser, aliases=["radare2"])
@pwndbg.commands.OnlyWithFile
def r2(arguments, no_seek=False, no_rebase=False):
    filename = pwndbg.gdblib.file.get_file(pwndbg.gdblib.proc.exe)

    # Build up the command line to run
    cmd = ["radare2"]
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
        print("Could not run radare2. Please ensure it's installed and in $PATH.")


parser = argparse.ArgumentParser(
    description="Execute stateful radare2 commands through r2pipe",
    epilog="Example: r2pipe pdf sym.main",
)
parser.add_argument("arguments", nargs="+", type=str, help="Arguments to pass to r2pipe")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def r2pipe(arguments):
    try:
        r2 = pwndbg.radare2.r2pipe()
        print(r2.cmd(" ".join(arguments)))
    except ImportError:
        print(message.error("Could not import r2pipe python library"))
    except Exception as e:
        print(message.error(e))
