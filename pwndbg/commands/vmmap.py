import gdb
import pwndbg.vmmap
import pwndbg.commands
import pwndbg.color

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def vmmap(map=None):
    int_map = None
    str_map = None
    if isinstance(map, str):
        str_map = map
    elif isinstance(map, (int, gdb.Value)):
        int_map = int(map)

    print(pwndbg.color.legend())

    for page in pwndbg.vmmap.get():
        if str_map and str_map not in page.objfile:
            continue
        if int_map and int_map not in page:
            continue

        print(pwndbg.color.get(page.vaddr, text=str(page)))
