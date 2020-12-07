import argparse
import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Put comments in assembly code")
parser.add_argument("--addr", metavar='address', default=None, type=str, help="Address to write comments")
parser.add_argument("comment", type=str, default=None,  help="The text you want to comment")

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def comm(addr=None, comment=None):
    if addr is None:
        addr = hex(pwndbg.regs.pc)
    try : 
        f = open(".gdb_comments", "a+")
    except :
        print(message.error("Permission denied to create file"))
    else :
        target = int(addr,0)

        if not pwndbg.memory.peek(target):
            print(message.error("Invalid Address %#x" % target))
        
        else:
            f.write("file:%s=" % pwndbg.proc.exe)
            f.write("%#x:%s\n" % (target, comment))

        f.close()
