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
