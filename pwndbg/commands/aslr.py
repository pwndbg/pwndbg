import pwndbg.vmmap
import pwndbg.commands
import pwndbg.color

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def aslr():
    status = pwndbg.color.red('OFF')
    if pwndbg.vmmap.aslr:
        status = pwndbg.color.green('ON')

    print("ASLR is %s" % status)

