import gdb
import gef.vmmap
import gef.commands
import gef.color

@gef.commands.ParsedCommand
@gef.commands.OnlyWhenRunning
def vmmap(map=None):
    int_map = None
    str_map = None
    if isinstance(map, str):
        str_map = map
    elif isinstance(map, (int, gdb.Value)):
        int_map = int(map)


    for page in gef.vmmap.get():
        if str_map and str_map not in page.objfile:
            continue
        if int_map and int_map not in page:
            continue

        print(gef.color.get(page.vaddr, text=str(page)))
    print(gef.color.legend())