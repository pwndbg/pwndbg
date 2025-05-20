from __future__ import annotations

import argparse
import subprocess

import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.radare2
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Launches radare2.")
parser.add_argument("--no-seek", action="store_true", help="Do not seek to current pc")
parser.add_argument(
    "--no-rebase",
    action="store_true",
    help="Do not set the base address for PIE according to the current mapping",
)
parser.add_argument("arguments", nargs="*", type=str, help="Arguments to pass to radare")


@pwndbg.commands.Command(
    parser,
    aliases=["radare2"],
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> r2 -- -S -AA
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
INFO: Analyze all flags starting with sym. and entry0 (aa)
[...]
INFO: Debugger commands disabled in sandbox mode
[0x0001d3d0]> help

Welcome to radare2!
[...]
    """,
)
@pwndbg.commands.OnlyWithFile
def r2(arguments, no_seek=False, no_rebase=False) -> None:
    filename = pwndbg.aglib.file.get_proc_exe_file()

    # Build up the command line to run
    cmd = ["radare2"]
    flags = ["-e", "io.cache=true"]
    if pwndbg.aglib.proc.alive:
        addr = pwndbg.aglib.regs.pc
        if pwndbg.aglib.elf.get_elf_info(filename).is_pie:
            if no_rebase:
                addr -= pwndbg.aglib.elf.exe().address
            else:
                flags.extend(["-B", hex(pwndbg.aglib.elf.exe().address)])
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
    description="Execute stateful radare2 commands through r2pipe.",
)
parser.add_argument("arguments", nargs="+", type=str, help="Arguments to pass to r2pipe")


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> r2pipe pdf @ sym.main
            ; ICOD XREF from entry0 @ 0x1d3e8(r)
┌ 6786: int main (uint32_t argc, char **argv, char **envp);
│ `- args(rdi, rsi, rdx) vars(21:sp[0x40..0x18c])
│           0x0001b920      f30f1efa       endbr64
│           0x0001b924      4157           push r15
│           0x0001b926      4156           push r14
│           0x0001b928      4155           push r13
│           0x0001b92a      4154           push r12
[...]
│           0x0001b966      85c0           test eax, eax
│       ┌─< 0x0001b968      7545           jne 0x1b9af
│       │   0x0001b96a      e8311b0100     call sym.xtrace_init
│       │   0x0001b96f      e80cff0000     call sym.check_dev_tty
│       │   ; CODE XREF from main @ 0x1b988(x)
│      ┌──> 0x0001b974      833dd1680f..   cmp dword [obj.debugging_login_shell], 0 ; [0x11224c:4]=0
│     ┌───< 0x0001b97b      743d           je 0x1b9ba
│     │╎│   0x0001b97d      bf03000000     mov edi, 3
[...]
    """,
)
@pwndbg.commands.OnlyWithFile
def r2pipe(arguments) -> None:
    try:
        r2 = pwndbg.radare2.r2pipe()
        print(r2.cmd(" ".join(arguments)))
    except ImportError:
        print(message.error("Could not import r2pipe python library. Is it installed?"))
    except Exception as e:
        print(message.error(e))
