import gdb
import pwndbg.argv
import pwndbg.commands


@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def argc():
    """
    Prints out the number of arguments.
    """
    print(pwndbg.argv.argc)

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def argv():
    """
    Prints out the contents of argv.
    """
    pwndbg.commands.telescope.telescope(pwndbg.argv.argv, pwndbg.argv.argc+1)

@pwndbg.commands.Command
def args():
    """
    Prints out the contents of argv.
    """
    argv()

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def envp():
    """
    Prints out the contents of the environment.
    """
    envp = pwndbg.argv.envp
    pwndbg.commands.telescope.telescope(pwndbg.argv.envp, pwndbg.argv.envc+1)

@pwndbg.commands.Command
def env():
    """
    Prints out the contents of the environment.
    """
    envp()

@pwndbg.commands.Command
def environ():
    """
    Prints out the contents of the environment.
    """
    envp()
