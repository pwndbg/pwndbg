from __future__ import annotations

import argparse
import subprocess

import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.rizin
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Launches rizin.")
parser.add_argument("--no-seek", action="store_true", help="Do not seek to current pc")
parser.add_argument(
    "--no-rebase",
    action="store_true",
    help="Do not set the base address for PIE according to the current mapping",
)
parser.add_argument("arguments", nargs="*", type=str, help="Arguments to pass to rizin")


@pwndbg.commands.Command(
    parser,
    aliases=["rizin"],
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> rz -- -AA
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls
[...]
[x] Enable constraint types analysis for variables
 -- Use 'e asm.offset=true' to show offsets in 16bit segment addressing mode.
[0x0001d3d0]>
    """,
)
@pwndbg.commands.OnlyWithFile
def rz(arguments, no_seek=False, no_rebase=False) -> None:
    filename = pwndbg.aglib.file.get_proc_exe_file()

    # Build up the command line to run
    cmd = ["rizin"]
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
        print("Could not run rizin. Please ensure it's installed and in $PATH.")


parser = argparse.ArgumentParser(
    description="Execute stateful rizin commands through rzpipe.",
)
parser.add_argument("arguments", nargs="+", type=str, help="Arguments to pass to rzpipe")


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> rzpipe pdf @ sym.main
            ; DATA XREF from entry0 @ 0x1d3e8
┌ int main(int argc, char **argv, char **envp);
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; arg char **envp @ rdx
[...]
│           ; var uint64_t var_18ch @ stack - 0x18c
│           ; var int64_t var_188h @ stack - 0x188
[...]
│           ; var int64_t canary @ stack - 0x40
│           0x0001b920      endbr64
│           0x0001b924      push  r15
│           0x0001b926      push  r14
│           0x0001b928      push  r13
│           0x0001b92a      push  r12
[...]
│           0x0001b966      test  eax, eax
│       ┌─< 0x0001b968      jne   0x1b9af
│       │   0x0001b96a      call  sym.xtrace_init
│       │   0x0001b96f      call  sym.check_dev_tty
│       │   ; CODE XREF from main @ 0x1b988
│      ┌──> 0x0001b974      cmp   dword [obj.debugging_login_shell], 0 ; [0x11224c:4]=0
│     ┌───< 0x0001b97b      je    0x1b9ba
│     │╎│   0x0001b97d      mov   edi, 3                               ; int s
[...]
    """,
)
@pwndbg.commands.OnlyWithFile
def rzpipe(arguments) -> None:
    try:
        rz = pwndbg.rizin.rzpipe()
        print(rz.cmd(" ".join(arguments)))
    except ImportError:
        print(message.error("Could not import rzpipe python library. Is it installed?"))
    except Exception as e:
        print(message.error(e))
