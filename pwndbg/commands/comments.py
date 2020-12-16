import argparse

import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Put comments in assembly code")
parser.add_argument("--addr", metavar='address', default=None, type=str, help="Address to write comments")
parser.add_argument("comment", type=str, default=None,  help="The text you want to comment")

file_lists = {} # This saves all comments.

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def comm(addr=None, comment=None):
    if addr is None:
        addr = hex(pwndbg.regs.pc)
    try: 
        with open(".gdb_comments", "a+") as f:
            target = int(addr,0)

            if not pwndbg.memory.peek(target):
                print(message.error("Invalid Address %#x" % target))
            
            else:
                f.write("file:%s=" % pwndbg.proc.exe)
                f.write("%#x:%s\n" % (target, comment))
                if not pwndbg.proc.exe in file_lists.keys():
                    file_lists[pwndbg.proc.exe] = {}
                file_lists[pwndbg.proc.exe][hex(target)] = comment
    except:
        print(message.error("Permission denied to create file"))

def init():
    try:
        with open(".gdb_comments","r") as f:
            text = f.read()
            text = text.split("\n")
            for i in range(len(text)-1):
                text1, text2 = text[i].split("=")

                # split Filename, comments
                filename = text1.split(":")[1]
                addr_comm = text2.split(":")

                if not filename in file_lists:
                    file_lists[filename] = {}

                file_lists[filename][addr_comm[0]] = addr_comm[1]

    except:
        pass 
