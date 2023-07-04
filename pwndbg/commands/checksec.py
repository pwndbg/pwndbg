import pwndbg.commands
import pwndbg.wrappers.checksec


@pwndbg.commands.ArgparsedCommand("Prints out the binary security settings using `checksec`.")
@pwndbg.commands.OnlyWithFile
def checksec() -> None:
    print(pwndbg.wrappers.checksec.get_raw_out())
