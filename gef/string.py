import gdb
import gef.types

def get(address):
    try:
        return gdb.Value(value).cast(gef.types.pchar).string()
    except Exception as e:
        print(e)
        return None