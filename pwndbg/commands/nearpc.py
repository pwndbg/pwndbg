from __future__ import annotations

import argparse

from gdb import lookup_symbol

import pwndbg.aglib.nearpc
from pwndbg.aglib.symbol import lookup_symbol_addr
import pwndbg.commands
from pwndbg.commands import CommandCategory

nearpc_lines = pwndbg.config.add_param(
    "nearpc-lines", 10, "number of lines to print for the nearpc command"
)

nearpc_backwards_lines = pwndbg.config.add_param(
    "nearpc-backwards-lines", 5, "number of lines before the pc to print for the nearpc command"
)

parser = argparse.ArgumentParser(description="Disassemble near a specified address.")
parser.add_argument(
    "pc",
    type=int,
    nargs="?",
    default=None,
    help="Address to disassemble near. If this is the only argument and the value provided is small enough, it is interpreted as lines instead.",
)
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines to disassemble.",
)
parser.add_argument(
    "-r",
    "--reverse",
    type=int,
    help="Number of lines to show before the address.",
)
parser.add_argument(
    "-t",
    "--total",
    type=int,
    help="Total number of lines to show. This results in dynamic number of forward instructions depending on how many cached instructions are used.",
)
parser.add_argument(
    "-e",
    "--emulate",
    action="store_true",
    help="Whether to emulate instructions to find the next ones or just linearly disassemble.",
)

parser.add_argument(
    "-n",
    "--no-branch",
    action="store_true",
    help="Disable showing branch visualizations.",
)

parser.add_argument(
    "-f",
    "--function",
    type=str,
    default=None,
    help="The name of the function to disassemble",
)

@pwndbg.commands.Command(parser, aliases=["pdisass", "u"], category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def nearpc(
    pc=None,
    lines=None,
    reverse=None,
    total=None,
    emulate=False,
    use_cache=False,
    linear=True,
    no_branch=False,
    function=None
) -> None:
    """
    Disassemble near a specified address.
    """

    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None and (pc is not None and int(pc) < 0x100):
        lines = pc
        pc = None

    # The explicitly requested number of lines to disassemble. None if not provided 
    input_lines = lines

    if pc is None:
        pc = pwndbg.aglib.regs.pc

    if lines is None:
        lines = int(nearpc_lines)

    back_lines = 0

    if reverse is None and total is None:
        back_lines = min(int(nearpc_backwards_lines), lines - 1)
    elif reverse is not None:
        back_lines = reverse
    elif total is not None:
        # -t was specified
        back_lines = min(int(nearpc_backwards_lines), total - 1)

    end_address = None
    if function is not None:
        address = lookup_symbol_addr(function)
        if address is not None:
            import gdb
            pc = address
            end_address = gdb.block_for_pc(address).superblock.superblock.end

            if input_lines is None:
                # If user didn't provide a minimum bound on number of instructions, make
                # sure we choose a number large enough to disassemble the entire function
                lines = end_address - pc
        else:
            print("Error: function {function} could not be found")
            return


    print(
        "\n".join(
            pwndbg.aglib.nearpc.nearpc(
                pc=pc,
                lines=lines,
                back_lines=back_lines,
                total_lines=total,
                emulate=emulate,
                repeat=nearpc.repeat,
                use_cache=use_cache,
                linear=linear,
                branch_visualization=not no_branch,
                end_address=end_address
            )
        )
    )


parser = argparse.ArgumentParser(
    description="Like nearpc, but will emulate instructions from the current $PC forward."
)
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to emulate near.")
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines to disassemble.",
)

parser.add_argument(
    "-r",
    "--reverse",
    type=int,
    help="Number of lines to show before the address.",
)

parser.add_argument(
    "-t",
    "--total",
    type=int,
    help="Total number of lines to show. This results in dynamic number of forward instructions depending on how many cached instructions are used.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def emulate(pc=None, lines=None, reverse=None, total=None, emulate_=True) -> None:
    """
    Like nearpc, but will emulate instructions from the current $PC forward.
    """
    nearpc.repeat = emulate.repeat
    nearpc(
        pc=pc,
        lines=lines,
        reverse=reverse,
        total=total,
        emulate=emulate_,
        use_cache=True,
        linear=False,
        no_branch=True,
    )
