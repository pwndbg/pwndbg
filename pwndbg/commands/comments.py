import argparse
import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Put comments in assembly code")
parser.add_argument("-addr", metavar='address', default=None, type=str, help="Address to write comments")
parser.add_argument("comment", type=str, default=None,  help="The text you want to comment")

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def comm(addr=None, comment=None):
    if(addr == None):
        addr = hex(pwndbg.regs.pc)
    f = open(".gdb_comments", "a+")

    target = int(addr,0)

    if not pwndbg.memory.peek(target):
        print(message.error("Invalid Address %#x" % target))
    
    else:
        f.write("%#x:%s\n" % (target, comment))
