from __future__ import annotations

import argparse

import pwndbg.commands
from pwndbg.commands import CommandCategory

description = "Modify the flags register."
epilog = """Examples:
  On X86/X64:
    setflag ZF 1        -- set zero flag
    setflag CF 0        -- unset carry flag

  On ARM:
    setflag Z 0         -- unset the Z cpsr/xpsr flag

  To see flags registers:
    info reg eflags     -- on x86/x64
    info reg cpsr/xpsr  -- on ARM (specific register may vary)

(This command supports flags registers that are defined for architectures in the pwndbg/regs.py file)
    """

parser = argparse.ArgumentParser(description=description, epilog=epilog)
parser.add_argument("flag", type=str, help="Flag for which you want to change the value")
parser.add_argument(
    "value",
    type=int,
    help="Value to which you want to set the flag - only valid options are 0 and 1",
)


@pwndbg.commands.Command(parser, aliases=["flag"], category=CommandCategory.REGISTER)
def setflag(flag: str, value: int) -> None:
    register_set = pwndbg.aglib.regs.current

    flag = flag.upper()
    for flag_reg, flags in register_set.flags.items():
        for flag_name, bit in flags.items():
            if flag_name == flag:
                # If the size is not specified, assume it's 1
                if isinstance(bit, int):
                    size = 1
                else:
                    assert len(bit) == 2
                    size = bit[1]
                    bit = bit[0]

                max_val = (1 << size) - 1
                if value > max_val:
                    print(f"Maximum value for flag is {max_val} (size={size})")
                    return

                old_val = int(pwndbg.aglib.regs[flag_reg])
                mask = max_val << bit
                bit_value = value << bit

                cleared_val = old_val & ~mask
                new_val = cleared_val | bit_value

                setattr(pwndbg.aglib.regs, flag_reg, new_val)
                print(
                    f"Set flag {flag}={value} in flag register {flag_reg} (old val={old_val:#x}, new val={new_val:#x})"
                )
                return
