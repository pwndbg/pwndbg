import pwndbg.memory
import pwndbg.regs
import pwndbg.types
import pwndbg.commands
import pwndbg.chain

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def telescope(address=None, count=8):
    if address is None:
        address = pwndbg.regs.sp

    if address < 100:
        count   = address
        address = pwndbg.regs.sp

    address = int(address)
    count   = int(count)

    reg_values = {r:v for (r,v) in pwndbg.regs.items()}
    # address    = pwndbg.memory.poi(pwndbg.types.ppvoid, address)
    ptrsize    = pwndbg.types.ptrsize

    start = address
    stop  = address + (count*ptrsize)
    step  = ptrsize

    # Find all registers which show up in the trace
    regs = {}
    for i in range(start, stop, step):
        regs[i] = []
        for reg, regval in reg_values.items():
            if i <= regval < i+ptrsize:
                regs[i].append(reg)
        regs[i] = ' '.join(regs[i])

    # Find the longest set of register information
    longest_regs = max(map(len, regs.values())) + 1

    # Print everything out
    for i,addr in enumerate(range(start, stop, step)):
        print("%02i:%04i|" % (i, addr-start),
              regs[addr].ljust(longest_regs),
              pwndbg.chain.format(addr))
