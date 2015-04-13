import gdb
import collections
import pwndbg.color
import pwndbg.disasm_powerpc
import pwndbg.memory
import pwndbg.arch
import pwndbg.ida
import pwndbg.symbol

Instruction = collections.namedtuple('Instruction', ['address', 'length', 'asm'])

def get(address, instructions=1):
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.memory.peek(address):
        return []

    raw = pwndbg.arch.disasm(address, address+0xffffffff, instructions)

    retval = []
    for insn in raw:
        addr   = int(insn['addr'])
        length = insn['length']
        asm    = insn['asm']

        split  = asm.split()

        if len(split) == 2:
            target = 0
            try:
                target = split[1]
                name   = pwndbg.symbol.get(int(target, 0))
                asm    = asm + ' <%s>' % name
            except ValueError:
                pass



        retval.append(Instruction(addr,length,asm))
    return retval

def near(address, instructions=1):
    # If we have IDA, we can just use it to find out where the various
    # isntructions are.
    if pwndbg.ida.available():
        head = address
        for i in range(instructions):
            head = pwndbg.ida.PrevHead(head)

        retval = []
        for i in range(2*instructions + 1):
            retval.append(get(head))
            head = pwndbg.ida.NextHead(head)


    # Find out how far back we can go without having a page fault
    distance = instructions * 8
    for start in range(address-distance, address):
        if pwndbg.memory.peek(start):
            break

    # Disassemble more than we expect to need, move forward until we have
    # enough instructions and we start on the correct spot
    insns = []
    while start < address:
        insns = get(start, instructions)
        if not insns:
            return []

        last = insns[-1]

        if last.address + last.length == address:
            break

        start += 1

    return insns[-instructions:] + get(address, instructions + 1)


calls = set([
'call', 'callq',
'bl','blx',
'jal'
])

returns = set([
'ret','retn','return',
'bx', # sometimes
'jr'
])

branches = calls | returns | set([
# Unconditional x86 branches
'call', 'callq',
'jmp',
'ret',
# Conditional x86 branches
'ja',  'jna',
'jae', 'jnae',
'jb',  'jnb',
'jbe', 'jnbe',
'jc',  'jnc',
'je',  'jne',
'jg',  'jng',
'jge', 'jnge',
'jl',  'jnl',
'jle', 'jnle',
'jo',  'jno',
'jp',  'jnp',
'jpe', 'jpo',
'js',  'jns',
'jz', 'jnz',
# ARM branches
'b', 'bl', 'bx', 'blx', 'bxj', 'b.w',
'beq', 'beq.w', 'bne', 'bmi', 'bpl', 'blt',
'ble', 'bgt', 'bge', 'bxne',
# MIPS branches
'j', 'jal', 'jr',
# SPARC
'ba', 'bne', 'be', 'bg', 'ble', 'bge', 'bl', 'bgu', 'bleu',
'jmpl'
])

branches = branches | pwndbg.disasm_powerpc.branches

def color(ins):
    asm = ins.asm
    mnem = asm.split()[0].strip().rstrip('+-')
    if mnem in branches:
        asm = pwndbg.color.yellow(asm)
        asm += '\n'
    return asm