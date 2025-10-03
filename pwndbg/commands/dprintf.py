import argparse
import pwndbg.commands
import pwndbg.aglib.symbol
import pwndbg.dbg
from pwndbg.commands import CommandCategory
import gdb

parse = argparse.ArgumentParser(description='Robust dprintf with caller ID and thread ID')

parse.add_argument('name', type=str, help='name of the function to do the enhanced dprintf')

parse.add_argument('--tid', action='store_true', help='include thread ID in ouptut')

parse.add_argument('-l', '--location', type=str, default=None, help='function or address at which to run dprintf. If none provided, use current frame')

parse.add_argument('arguments', nargs=argparse.REMAINDER, help='format string and value tokens to prevent errors')

parse.add_argument('--values', type=str, help='Extra args for dprintf (e.g. $rdi $rax)')

parse.add_argument('-d', '--depth', dest='depth', type=int, default=0, help='Depth of backtrace')

def caller_info(depth):
     if depth <= 0:
        return ''
     else:
        frame = pwndbg.dbg.selected_frame() #capture the root frame
        caller = frame #save the root frame so we can navigate to the specified depth
        if not frame:
           return ''

        for i in range(0, depth):
            try:
                parent = frame.parent()
            except Exception:
                return ''
            if not parent:
                return ''
            frame = parent
      #after this loop, we have captured the frame at the specified depth
      #now we get the info of the frame
     pc = frame.pc()
     symbol = pwndbg.aglib.symbol.resolve_addr(int(pc))
     return str(symbol)

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command(parse, category=CommandCategory.BREAKPOINT)

def dp(name, arguments, values, tid, depth, location):

     #print(f'Name:{name}, Arguments:{arguments}, Get ThreadID:{tid}, depth:{depth}')
     if depth == 0: #if depth is 0, we simply call dprintf like normal
        #GET THREAD ID
        sel = gdb.selected_thread()
        tid_val = sel.ptid[1]
        #print(f'Current Command: dprintf {name}, "{location}\n", {values}')
        print(gdb.execute(f'dprintf {name}, "{location}", {values}', to_string=True))
        print(f'[TID: {tid_val}] {location}')

     else: #otherwise we must iterate to the proper depth
        print('Retrieving Caller Info')
        caller = caller_info(depth)
        sel = gdb.selected_thread()
        tid_val = sel.ptid[1]
        #print(f'Current Command: dprintf {name}, "{location}\n", {values}')
        print(gdb.execute(f'dprintf {name}, "{caller}", {values}', to_string=True))
        print(f'[TID: {tid_val}] {caller}')
        #print(caller)
