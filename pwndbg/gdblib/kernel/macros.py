import gdb


def offset_of(typename: str, fieldname: str):
    ptr_type = gdb.lookup_type(typename).pointer()
    dummy = gdb.Value(0).cast(ptr_type)
    return int(dummy[fieldname].address)


def container_of(ptr, typename: str, fieldname: str):
    ptr_type = gdb.lookup_type(typename).pointer()
    obj_addr = int(ptr) - offset_of(typename, fieldname)
    return gdb.Value(obj_addr).cast(ptr_type)


def for_each_entry(head, typename, field):
    addr = head["next"]
    while addr != head.address:
        yield container_of(addr, typename, field)
        addr = addr.dereference()["next"]


def swab(x):
    return int(
        ((x & 0x00000000000000FF) << 56)
        | ((x & 0x000000000000FF00) << 40)
        | ((x & 0x0000000000FF0000) << 24)
        | ((x & 0x00000000FF000000) << 8)
        | ((x & 0x000000FF00000000) >> 8)
        | ((x & 0x0000FF0000000000) >> 24)
        | ((x & 0x00FF000000000000) >> 40)
        | ((x & 0xFF00000000000000) >> 56)
    )
