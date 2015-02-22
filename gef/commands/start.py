import gdb
import gef.commands

@gef.commands.ParsedCommand
@gef.commands.OnlyWhenRunning
def start():

    entries = ["main"]
    main_addr = peda.main_entry()
    if main_addr:
        entries += ["*0x%x" % main_addr]
    entries += ["__libc_start_main@plt"]
    entries += ["_start"]
    entries += ["_init"]

    started = 0
    for e in entries:
        out = peda.execute_redirect("tbreak %s" % e)
        if out and "breakpoint" in out:
            peda.execute("run %s" % ' '.join(arg))
            started = 1
            break

    if not started: # try ELF entry point or just "run" as the last resort
        elf_entry = peda.elfentry()
        if elf_entry:
            out = peda.execute_redirect("tbreak *%s" % elf_entry)

        peda.execute("run")
