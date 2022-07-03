import argparse
import gdb
import pwndbg.commands

parser = argparse.ArgumentParser(description="Modify register flags",
                                epilog="flags ZF 1")
parser.add_argument('flag', type=str,
                    help='Flag for which you want to change the value')
parser.add_argument('value', type=int,
                    help='Value to which you want to set the flag - only valid options are 0 and 1')

flags = {
            "CF": 0,
            "PF": 2,
            "AF": 4,
            "ZF": 6,
            "SF": 7,
            "TF": 8,
            "IF": 9,
            "DF": 10,
            "OF": 11,
        }

@pwndbg.commands.ArgparsedCommand(parser, aliases=["flag"])
def setflag(flag, value):
    if value not in [0, 1]:
        print("can only set flag bit to 0 or 1")
        return

    if flag.upper() not in flags.keys():
        print("%s not a valid flag" % flag)
        return

    if value == 1:
        gdb.execute("set $eflags |= (1 << %d)" % flags[flag.upper()])
    elif value == 0:
        gdb.execute("set $eflags &= ~(1 << %d)" % flags[flag.upper()])
