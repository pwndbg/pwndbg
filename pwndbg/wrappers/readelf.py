import pwndbg.wrappers

cmd_name = "readelf"


@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def get_jmpslots():
    local_path = pwndbg.gdblib.file.get_file(pwndbg.gdblib.proc.exe)
    cmd = get_jmpslots.cmd + ["--relocs", local_path]
    readelf_out = pwndbg.wrappers.call_cmd(cmd)

    return filter(_extract_jumps, readelf_out.splitlines())


def _extract_jumps(line):
    """
     Checks for records in `readelf --relocs <binary>` which has type e.g. `R_X86_64_JUMP_SLO`
     NOTE: Because of that we DO NOT display entries that are not writeable (due to FULL RELRO)
     as they have `R_X86_64_GLOB_DAT` type.

    It might be good to display them separately in the future.
    """
    try:
        if "JUMP" in line.split()[2]:
            return line
        else:
            return False
    except IndexError:
        return False
