from __future__ import annotations

import pwndbg.commands
import pwndbg.gdblib.file
import pwndbg.wrappers.checksec


@pwndbg.commands.ArgparsedCommand("Prints out the binary security settings using `checksec`.")
@pwndbg.commands.OnlyWithFile
def checksec() -> None:
    print(pwndbg.wrappers.checksec.get_raw_out(pwndbg.gdblib.file.get_proc_exe_file()))
