from __future__ import print_function
from __future__ import unicode_literals
from sys import stdout, stderr

import argparse
import re
import subprocess
import tempfile

import gdb
import pwndbg.commands
import pwndbg.vmmap

rs = None

parser = argparse.ArgumentParser(description="Gadget search, ropchaining and more using ropper",
                                epilog="Examples: \"ropper --search 'pop rdi'\", \"ropper --search 'mov e?x'\", \"ropper --ropchain 'execve'\", \"ropper --ropchain 'mprotect address=0xbfff0000 size=0x20fff'\"")
parser.add_argument('--gadgets',
                    help='Prints all gadgets found in the binary', action='store_true')
parser.add_argument('--search', type=str,
                    help='String to search for gadgets. ? - any character; %  - any string. Example: ropper --search "mov [e?x]"')
parser.add_argument('--jmp', type=str,
                    help='Looks for jmp reg or equivalent instructions. Example: ropper --jmp esp,eax', metavar='<reg[,<reg>]>')
parser.add_argument('--opcode', type=str,
                    help='Looks for the specified opcode. Valid formats examples: ffe4, ffe?, ff??. Example: ropper --opcode ffe4', metavar='<reg[,<reg>]>')
parser.add_argument('--instructions', type=str,
                    help='Looks for the opcode of the given instructions in the binary (keystone is needed. www.keystone-engine.org). Example: ropper --instructions "mov eax, 4; jmp esp"', metavar='<reg[,<reg>]>')
parser.add_argument('--set', type=str, metavar='<settings>',
                    help="""'sets a setting. setting[=value]] [setting[=value]]...'        
If no value is given, this option is set to the default
                    """)
parser.add_argument('--settings',
                     help='Prints all settings',
                     action='store_true')
parser.add_argument('--ropchain', 
                    help="Generates a ropchain [generator parameter=value[ parameter=value]]. (execve, mprotect(address,size))", 
                    metavar='<generator>', type=str)
parser.add_argument('--asm', type=str,
                    help='Assemble instructions. The architecture of the opened file is used (keystone is needed. www.keystone-engine.org). Example: ropper --asm "jmp esp"', metavar='<code>')
parser.add_argument('--out', type=str, help="Specify the output format for asm. (hex, string, raw; default: hex)", default='hex', metavar='<format>')
parser.add_argument('--disasm', type=str,
                    help='Disassemble instructions. The architecture of the opened file is used. Example: ropper --disasm ffe4', metavar='<opcode>')


def parse_settings(settings):
    to_return = {}
    for line in settings.split(' '):
        opt = line.split('=')
        if opt[0] in ['all','badbytes','type', 'color', 'detailed', 'cfg_only', 'inst_count']:
            if len(opt) > 1:
                if opt[0] in ['all', 'color', 'detailed']:
                    to_return[opt[0]] = opt[1].strip().capitalize() == 'True'
                elif opt[0] in ['inst_count']:
                    to_return[opt[0]] = int(opt[1])
                else:
                    to_return[opt[0]] = opt[1]

            else:
                to_return[opt[0]] = None
        else:
            print('Invalid setting: %s' % opt[0])

    return to_return

def create_chain(params):
    split = params.split(' ')
    generator = split[0]
    options = {}
    if len(split) > 1:
        for option in split[1:]:
            key, value = option.split('=')
            options[key] = value
    print(rs.createRopChain(generator, options))

def set_settings(set):
    sets = parse_settings(set)
    need_to_reload = False
    for key, value in sets.items():
        rs.options[key] = value
        if key in ['inst_count','type']:
            need_to_reload = True

    if need_to_reload:
        rs.loadGadgetsFor()
    return

def print_settings():
    description = {'inst_count' : 'Max count of instructions in a gadget',
                    'color' : 'Colored output (true|false)',
                    'badbytes' : 'These bytes should not be in gadget addresses (format example: 000a0d)',
                    'detailed' : 'Detailed output format for gadgets (true|false)',
                    'all' : 'Show all gadgets. double gadgets are not removed',
                    'type' : 'Type of gadgets (rop, jop, sys, all)'
                }
    for key, value in rs.options.items():
        if not key == 'cfg_only':
            print("%s - %s\t%s" % (key+' '*(10-len(key)), str(value)+' '*(6-len(str(value))), description[key]))

    print()
    print('How to set settings:')
    print('ropper --set badbytes=00 all=true')
    print()
    print('How to clear/reset settings:')
    print('ropper --set badbytes')


def print_gadgets_from_dict(gadgetsdict):
    for file, opcodes in gadgetsdict.items():
        print(file)
        for gadget in opcodes:
            print(gadget.simpleString())

@pwndbg.commands.ArgparsedCommand(parser)
def ropper(gadgets, search, jmp, opcode, instructions, set, settings, ropchain, asm, out, disasm):
    with tempfile.NamedTemporaryFile() as corefile:
        global rs
        # check if ropper is installed
        try:
            import ropper
        except ImportError:
            print("ropper is not installed.\nPlease look at https://scoding.de/ropper")
            return

        # check if RopperService is available in the installed version.
        if not hasattr(ropper, 'RopperService'):
            print("Please update ropper.")
            return

        if not rs:
            rs = ropper.RopperService(callbacks=CallbackClass())

        # If the process is running, dump a corefile so we get actual addresses.
        if pwndbg.proc.alive:
            filename = corefile.name
            gdb.execute('gcore %s' % filename)
        else:
            filename = pwndbg.proc.exe

        # If no binary was specified, we can't do anything
        if not filename:
            print("No file to get gadgets from")
            return

        try:
            if not rs.getFileFor(filename):
                for file in rs.files:
                    rs.removeFile(file)

                rs.addFile(filename)

            if gadgets:
                if not rs.getFileFor(filename).loaded:
                    rs.loadGadgetsFor()
                rs.printGadgetsFor(filename)
            elif jmp:
                print_gadgets_from_dict(rs.searchJmpReg(regs=jmp.split(',')))
            elif opcode:
                print_gadgets_from_dict(rs.searchOpcode(opcode=opcode).items())
            elif instructions:
                print_gadgets_from_dict(rs.searchInstructions(code=instructions.encode('ascii')))
            elif settings:
                print_settings()
            elif set:
                set_settings(set)
            elif ropchain:
                create_chain(ropchain)
            elif search:
                if not rs.getFileFor(filename).loaded:
                    rs.loadGadgetsFor(filename)
                found = False
                for f, g in rs.search(search=search, name=filename):
                    found = True
                    print(g)
                if not found:
                    print('No gadgets found for: %s' % search)
            elif asm:
                arch = 'x86'
                f = rs.getFileFor(filename)
                if f:
                    arch = str(f.arch)
                print(rs.asm(asm.encode('ascii'),arch=arch, format=out))
            elif disasm:
                arch = 'x86'
                f = rs.getFileFor(filename)
                if f:
                    arch = str(f.arch)
                print(rs.disasm(opcode=disasm,arch=arch))
            else:
                print(parser.print_help())
    
        except BaseException as e:
            print(e)


class CallbackClass(object):
    """Callback class for RopperService
    
    This class is used for different callbacks in ropper like progress when searching rop gadgets.
    """

    def printProgress(self, message, progress):
        stdout.write('\r%s %s %s' % (pwndbg.color.green('[LOAD]'), message, str(int(progress * 100))))
        stdout.flush()

    def printInfo(self, message):
        print(pwndbg.color.green('[INFO]'), message)

    def __gadgetSearchProgress__(self, section, gadgets, progress):
        if gadgets is not None:
            self.printProgress('loading...', progress)

            if progress == 1.0:
                print()
        else:
            self.printInfo(
                'Load gadgets for section: ' + section.name)

    def __deleteDoubleGadgetsProgress__(self, gadget, added, progress):
        self.printProgress('removing double gadgets...', progress)
        if progress == 1.0:
            print()

    def __filterCfgGadgetsProgress__(self, gadget, added, progress):
        self.printProgress('filtering cfg gadgets...', progress)
        if progress == 1.0:
            print()

    def __filterBadBytesGadgetsProgress__(self, gadget, added, progress):
        self.printProgress('filtering badbytes...', progress)
        if progress == 1.0:
            print()

    def __ropchainMessages__(self, message):
        if message.startswith('[*]'):
            stdout.write('\r' + message)
            stdout.flush()
        else:
            print(message)

