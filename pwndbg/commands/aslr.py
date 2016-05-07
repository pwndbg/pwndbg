from __future__ import print_function
import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.proc
import pwndbg.vmmap


@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def aslr(on_or_off=None):
    """
    Check the current ASLR status, or turn it on/off.

    Does not take effect until the program is restarted.
    """
    options = {'on':'off', 'off':'on'}

    if on_or_off is not None:
        on_or_off = on_or_off.lower()
        if on_or_off not in options:
            print('Valid options are %s' % ', '.join(map(repr, options.keys())))
        else:
            gdb.execute('set disable-randomization %s' % options[on_or_off], from_tty=False, to_string=True)

            if pwndbg.proc.alive:
                print("Change will take effect when the process restarts")

    aslr = pwndbg.vmmap.check_aslr()
    status = pwndbg.color.red('OFF')

    if aslr:
        status = pwndbg.color.green('ON')

    print("ASLR is %s" % status)
