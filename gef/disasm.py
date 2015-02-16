import gdb
import collections

Instruction = collections.namedtuple('Instruction', ['address', 'length', 'asm'])

def get(address, instructions=1):
    address = int(address)
    raw = gdb.selected_frame().architecture().disassemble(address, address+0xffffffff, instructions)
    retval = []
    for insn in raw:
        retval.append(Instruction(insn['addr'],insn['length'], insn['asm']))
    return retval
