import argparse
from argparse import RawTextHelpFormatter

import pwndbg.commands

description = "Modify the flags register"
epilog = """Examples:
  On X86/X64:
    setflag ZF 1        -- set zero flag
    setflag CF 0        -- unset carry flag

  On ARM:
    setflag Z 0         -- unset the Z cpsr/xpsr flag

  To see flags registers:
    info reg eflags     -- on x86/x64
    info reg cspr/xpsr  -- on ARM (specific register may vary)

(This command supports flags registers that are defined for architectures in the pwndbg/regs.py file)
    """

parser = argparse.ArgumentParser(
    description=description, epilog=epilog, formatter_class=RawTextHelpFormatter
)
parser.add_argument("flag", type=str, help="Flag for which you want to change the value")
parser.add_argument(
    "value",
    type=int,
    help="Value to which you want to set the flag - only valid options are 0 and 1",
)


@pwndbg.commands.ArgparsedCommand(
    parser,
    aliases=["flag"],
)
def setflag(flag, value):
    if value not in [0, 1]:
        print("can only set flag bit to 0 or 1")
        return

    register_set = pwndbg.gdblib.regs.reg_sets[pwndbg.gdblib.arch.current]

    flag = flag.upper()
    for flag_reg, flags in register_set.flags.items():
        for (flag_name, flag_bit) in flags.items():
            if flag_name == flag:
                old_flags_reg_value = pwndbg.gdblib.regs[flag_reg]
                bit_value = 1 << flag_bit

                if value == 1:
                    # novermin
                    new_flags_reg_value = old_flags_reg_value | bit_value
                else:
                    new_flags_reg_value = old_flags_reg_value & ~bit_value

                setattr(pwndbg.gdblib.regs, flag_reg, new_flags_reg_value)
                print(
                    "Set flag %s=%d in flag register %s (old val=%#x, new val=%#x)"
                    % (flag, value, flag_reg, old_flags_reg_value, new_flags_reg_value)
                )
                return

    print("The %s not a valid/recognized flag" % flag)
