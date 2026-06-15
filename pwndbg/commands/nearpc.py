from __future__ import annotations

import argparse

import pwndbg.aglib.nearpc
import pwndbg.aglib.symbol
import pwndbg.commands
import pwndbg.dbg_mod
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


# sentinel value used when `--function` option is given without an argument
class CurrentFunction:
    pass


CURRENT_FUNCTION = CurrentFunction()


parser.add_argument(
    "-f",
    "--function",
    type=int,
    nargs="?",
    default=None,
    const=CURRENT_FUNCTION,
    help="Disassemble an entire function. Takes an expression (such as a function name or address) and disassembles the function surrounding the evaluated address, defaulting to the pc of the selected frame.",
)


@pwndbg.commands.Command(parser, aliases=["pdisass", "u"], category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def nearpc(
    pc: int | None = None,
    lines: int | None = None,
    reverse: int | None = None,
    total: int | None = None,
    emulate: bool = False,
    use_cache: bool = False,
    linear: bool = True,
    no_branch: bool = False,
    function: int | None = None,
) -> None:
    """
    Disassemble near a specified address.
    """
    # nearpc is flexible in the first argument (it can be an address or the number of lines to disassemble).
    # Save the first argument, which depending on the context might be the explicitly requested number of lines to disassemble.
    # None if not provided
    first_input_argument = pc

    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None and (pc is not None and int(pc) < 0x100):
        lines = pc
        pc = None

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
    address_to_highlight = None
    if function is not None:
        # Emulate GDB behavior of "disass" - it disassembles the entire function in which
        # the input address resides. User can input integer or string name of function, or an expression
        address_to_highlight = int(pwndbg.dbg.selected_frame().pc())
        if function is CURRENT_FUNCTION:
            function = address_to_highlight

        boundaries = pwndbg.aglib.symbol.resolve_function_boundaries(function)
        if boundaries is None:
            print(f"Error: function boundaries of '{hex(function)}' could not be found")
            return
        pc, end_address = boundaries

        if end_address < pc:
            print(f"Error: function boundaries  of '{hex(function)}' could not be found")
            return

        if end_address - pc > 0x1000:
            print(
                f"Warning: detected very long function of length {hex(end_address - pc)} bytes. This may block for a while."
            )

        if first_input_argument is None:
            # If user didn't provide a minimum bound on number of instructions, make
            # sure we choose a number large enough to disassemble the entire function
            lines = end_address - pc
        back_lines = 0

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
                address_to_highlight=address_to_highlight,
                end_address=end_address,
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
