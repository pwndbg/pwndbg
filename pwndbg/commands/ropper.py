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

parser = argparse.ArgumentParser(description="Gadget search with ropper",
                                epilog="Examples: \"ropper --search 'pop rdi'\", \"ropper --search 'mov e?x'\", \"ropper --ropchain 'execve'\", \"ropper --ropchain 'mprotect address=0xbfff0000 size=0x20fff'\"")
parser.add_argument('--search', type=str,
                    help='String to grep the output for')
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

def parse_settings(settings):
    to_return = {}
    for line in settings.split(' '):
        opt = line.split('=')
        if opt[0] in ['all','badbytes','type', 'color', 'detailed', 'cfg_only', 'inst_count']:
            if len(opt) > 1:
                if opt[0] in ['all', 'color', 'detailed']:
                    to_return[opt[0]] = bool(opt[1])
                elif opt[0] in ['inst_count']:
                    to_return[opt[0]] = int(opt[1])
                else:
                    to_return[opt[0]] = opt[1]

            else:
                to_return[opt[0]] = None
        else:
            print('Invalid setting: %s' % opt[0])

    return to_return


@pwndbg.commands.ArgparsedCommand(parser)
def ropper(search, set, settings, ropchain):
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
            if settings:
                for key, value in rs.options.items():
                    print("%s: %s" % (key, value))
                return

            if not rs.getFileFor(filename):
                for file in rs.files:
                    rs.removeFile(file)

                rs.addFile(filename)
                rs.loadGadgetsFor(filename)

            if set:
                sets = parse_settings(set)
                need_to_reload = False
                for key, value in sets.items():
                    rs.options[key] = value
                    if key in ['inst_count','type']:
                        has_to_reload = True

                if has_to_reload:
                    rs.loadGadgetsFor(file)
                return

            if ropchain:
                split = ropchain.split(' ')
                generator = split[0]
                options = {}
                if len(split) > 1:
                    for option in split[1:]:
                        key, value = option.split('=')
                        options[key] = value
                print(rs.createRopChain(generator, options))
                return

            if search:
                for f, g in rs.search(search=search, name=filename):
                    print(g)
                return

            rs.printGadgetsFor(filename)
        except BaseException as e:
            print(e)


class CallbackClass(object):

    def __init__(self):
        self.__console = ConsolePrinter()

    def __gadgetSearchProgress__(self, section, gadgets, progress):
        if gadgets is not None:
            self.__console.printProgress('loading...', progress)

            if progress == 1.0:
                self.__console.finishProgress()
        else:
            self.__console.printInfo(
                'Load gadgets for section: ' + section.name)

    def __deleteDoubleGadgetsProgress__(self, gadget, added, progress):
        self.__console.printProgress('removing double gadgets...', progress)
        if progress == 1.0:
            self.__console.finishProgress()

    def __filterCfgGadgetsProgress__(self, gadget, added, progress):
        self.__console.printProgress('filtering cfg gadgets...', progress)
        if progress == 1.0:
            self.__console.finishProgress()

    def __filterBadBytesGadgetsProgress__(self, gadget, added, progress):
        self.__console.printProgress('filtering badbytes...', progress)
        if progress == 1.0:
            self.__console.finishProgress()

    def __ropchainMessages__(self, message):
        if message.startswith('[*]'):
            self.__console.puts('\r' + message)
        else:
            self.__console.printInfo(message)

class ConsolePrinter(object):

    def __init__(self, out=stdout, err=stderr):
        super(ConsolePrinter, self).__init__()
        self._out = out
        self._err = err

    def putsErr(self, *args):
        for i, arg in enumerate(args):
            self._err.write(str(arg))
            if i != len(args) - 1:
                self._err.write(' ')
        self._err.flush()

    def puts(self, *args):

        for i, arg in enumerate(args):
            self._out.write(str(arg))
            if i != len(args) - 1:
                self._out.write(' ')
        self._out.flush()

    def println(self, *args):

        self.puts(*args)
        self._out.write('\n')

    def printlnErr(self, *args):

        self.putsErr(*args)
        self._err.write('\n')

    def printHelpText(self, cmd, desc):
        self.println('{}  -  {}\n'.format(cmd, desc))

    def printMessage(self, mtype, message):
        self.printlnErr(mtype, message)

    def printError(self, message):
        self.printMessage(pwndbg.color.red('[ERROR]'), message)

    def printInfo(self, message):
        self.printMessage(pwndbg.color.green('[INFO]'), message)

    def startProgress(self, message=None):
        if message:
            self.printInfo(message)

    def printProgress(self, message, progress):
        self.putsErr('\r' + pwndbg.color.green('[LOAD]'),message, str(int(progress * 100)) + '%')

    def finishProgress(self, message=None):
        self.printlnErr('')
        if message:
            self.printInfo(message)