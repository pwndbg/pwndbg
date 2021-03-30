import pwndbg.elf

radare2 = {}


def r2pipe(filename):
    r2 = radare2.get(filename)
    if r2:
        return r2
    import r2pipe
    flags = ['-e', 'io.cache=true']
    if pwndbg.elf.get_elf_info(filename).is_pie and pwndbg.elf.exe():
        flags.extend(['-B', hex(pwndbg.elf.exe().address)])
    r2 = r2pipe.open(filename, flags=flags)
    radare2[filename] = r2
    r2.cmd("aaaa")
    return r2
