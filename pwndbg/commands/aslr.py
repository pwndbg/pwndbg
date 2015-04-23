import pwndbg.color
import pwndbg.commands
import pwndbg.vmmap


@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def aslr():
    status = pwndbg.color.red('OFF')
    if pwndbg.vmmap.aslr:
        status = pwndbg.color.green('ON')

    print("ASLR is %s" % status)
