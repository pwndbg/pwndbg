from __future__ import annotations

import argparse
from typing import Optional

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.chain
import pwndbg.commands
import pwndbg.dbg
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Dumps the elements of a linked list.

This command traverses the linked list beginning at a given element, dumping its
contents and the contents of all the elements that come after it in the list.
Traversal is configurable and can handle multiple types of linked lists, but will
always stop when a cycle is detected.

The path to the first element can be any GDB expression that evaluates to either
the first element directly, or a to pointer to it. The next element is the name
of the field containing the next pointer, in either the structure itself or in
the structure given by --inner.

An address value may be given with --sentinel that signals the end of the list.
By default, the value used is NULL (0).

If only one field inside each node is desired, it can be printed exclusively by
specifying its name with --field.

This command supports traversing three types of linked lists, classified by how
the next pointer can be found in the structure and what type it is:
    1 - Next pointer is field of structure, type is the same as structure.
    2 - Next pointer is field of inner nested structure, pointed to type is the
        same as outer structure.
    3 - Next pointer is field of inner nested structure, pointed to type is the
        same as inner structure.
Types 2 and 3 require --inner to be specified.

Example 1:

```
struct node {
    int value;
    struct node *next;
};
struct node node_c = { 2, NULL };
struct node node_b = { 1, &node_c };
struct node node_a = { 0, &node_b };
```

pwndbg> plist node_a next
0x4000011050 <node_a>: {
  value = 0,
  next = 0x4000011040 <node_b>
}
0x4000011040 <node_b>: {
  value = 1,
  next = 0x4000011010 <node_c>
}
0x4000011010 <node_c>: {
  value = 2,
  next = 0x0
}

Example 2:

```
struct node_inner_a {
    struct node_inner_a *next;
};
struct inner_a_node {
    int value;
    struct node_inner_a inner;
};
struct inner_a_node inner_a_node_c = { 2, { NULL } };
struct inner_a_node inner_a_node_b = { 1, { &inner_a_node_c.inner } };
struct inner_a_node inner_a_node_a = { 0, { &inner_a_node_b.inner } };
```

pwndbg> plist inner_a_node_a -i inner next
0x4000011070 <inner_a_node_a>: {
  value = 0,
  inner = {
    next = 0x4000011068 <inner_a_node_b+8>
  }
}
0x4000011060 <inner_a_node_b>: {
  value = 1,
  inner = {
    next = 0x4000011028 <inner_a_node_c+8>
  }
}
0x4000011020 <inner_a_node_c>: {
  value = 2,
  inner = {
    next = 0x0
  }
}

Example 3:

```
struct inner_b_node;
struct node_inner_b {
    struct inner_b_node *next;
};
struct inner_b_node {
    int value;
    struct node_inner_b inner;
};
struct inner_b_node inner_b_node_c = { 2, { NULL } };
struct inner_b_node inner_b_node_b = { 1, { &inner_b_node_c } };
struct inner_b_node inner_b_node_a = { 0, { &inner_b_node_b } };
```

pwndbg> plist inner_b_node_a -i inner next
0x4000011090 <inner_b_node_a>: {
  value = 0,
  inner = {
    next = 0x4000011080 <inner_b_node_b>
  }
}
0x4000011080 <inner_b_node_b>: {
  value = 1,
  inner = {
    next = 0x4000011030 <inner_b_node_c>
  }
}
0x4000011030 <inner_b_node_c>: {
  value = 2,
  inner = {
    next = 0x0
  }
}

""",
)
parser.add_argument(
    "path",
    type=str,
    help="The first element of the linked list",
)
parser.add_argument(
    "next", type=str, help="The name of the field pointing to the next element in the list"
)
parser.add_argument(
    "-s",
    "--sentinel",
    dest="sentinel",
    type=int,
    default=0,
    help="The address that stands in for an end of list marker in a non-cyclic list",
)
parser.add_argument(
    "-i",
    "--inner",
    dest="inner_name",
    type=str,
    help="The name of the inner nested structure where the next pointer is stored",
)
parser.add_argument(
    "-f",
    "--field",
    dest="field_name",
    type=str,
    help="The name of the field to be displayed, if only one is desired",
)
parser.add_argument(
    "-o",
    "--offset",
    dest="offset",
    type=int,
    default=0,
    help="The offset of the first list element to display. Defaults to zero.",
)
parser.add_argument(
    "-c",
    "--count",
    dest="count",
    type=int,
    default=None,
    help="The number of elements to display. Defaults to the value of dereference-limit.",
)


@pwndbg.commands.Command(parser, command_name="plist", category=CommandCategory.MISC)
def plist(
    path: str,
    next: str,
    sentinel: int,
    inner_name: Optional[str],
    field_name: Optional[str],
    offset: int,
    count: Optional[int] = None,
) -> None:
    # Have GDB parse the path for us and check if it's valid.
    try:
        first = pwndbg.dbg.selected_frame().evaluate_expression(path)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"{e}"))
        return

    if first.is_optimized_out:
        print(message.error(f"{path} has been optimized out"))
        return

    if count is None:
        count = pwndbg.config.dereference_limit
    if count <= 0:
        print("count <= 0: not displaying any elements")
        return

    # We suport being passed either a pointer to the first structure or the
    # structure itself, for the sake of convenience. But we don't bother with
    # chains of pointers. Additionally, we pick the correct separator to use
    # for the error mesages.
    sep = "."
    deref = ""
    if first.type.code == pwndbg.dbg_mod.TypeCode.POINTER:
        sep = "->"
        deref = "*"
        try:
            first = first.dereference()
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Pointer at {path} could not be dereferenced: {e}"))
            return

    if first.type.code == pwndbg.dbg_mod.TypeCode.POINTER:
        print(message.error(f"{path} is not a value or a single pointer to one"))
        return

    if first.address is None:
        print(message.error(f"{deref}{path} is not addressable"))
        return

    if first.is_optimized_out:
        print(message.error(f"{deref}{path} has been optimized out"))
        return

    # If there is an inner element we have to use, find it.
    inner = None
    inner_sep = ""
    if inner_name is not None:
        try:
            inner = first[inner_name]
            inner_sep = "->"
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Cannot find component {inner_name} in {path}: {e}"))
            return
        if inner.is_optimized_out:
            print(message.error(f"{path}{sep}{inner_name} has been optimized out"))
            return

    # Resolve the pointer to the next structure, wherever it may be, and make
    # sure that we can use it to traverse the linked list.
    next_ptr_loc = first
    next_ptr_name = next
    try:
        if inner is None:
            next_ptr = first[next]
        else:
            next_ptr = inner[next]
            next_ptr_loc = inner
            next_ptr_name = f"{inner_name}.{next}"
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Cannot find component {next_ptr_name} in {path}: {e}"))
        return

    if next_ptr.is_optimized_out:
        print(message.error(f"{path}{sep}{next_ptr_name} has been optimized out"))
        return
    if next_ptr.type.code != pwndbg.dbg_mod.TypeCode.POINTER:
        print(message.error(f"{path}{sep}{next_ptr_name} is not a pointer"))
        return

    # If the user wants a specific field to be displayed, resolve it.
    field_offset = None
    field_type = None
    if field_name is not None:
        try:
            field = first[field_name]
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Cannot find component {field_name} in {path}: {e}"))
            return
        field_type = field.type

        bit_offset = bit_offset_of_field(first, field_name)
        if bit_offset is None:
            print(
                message.error(
                    f"{path}{sep}{field_name} has no known offset \
                from {deref}{path}"
                )
            )
            return
        byte_offset = get_byte_offset(bit_offset)
        if byte_offset is None:
            print(
                message.error(
                    f"{field_name} is a non-whole number of bytes \
                {bit_offset} bits) offset from {deref}{path}"
                )
            )
            return
        field_offset = byte_offset

    # Figure out the offset of the inner structure, if any, in typeof(first).
    inner_offset = 0
    if inner is not None:
        bit_offset = bit_offset_of_field(first, inner_name)
        if bit_offset is None:
            print(
                message.error(
                    f"{path}{sep}{inner_name} has no known offset \
                from {deref}{path}"
                )
            )
            return
        byte_offset = get_byte_offset(bit_offset)
        if byte_offset is None:
            print(
                message.error(
                    f"{inner_name} is a non-whole number of bytes \
                {bit_offset} bits) offset from {deref}{path}"
                )
            )
            return
        inner_offset = byte_offset

    # Figure out the offset of the next pointer in its containing type.
    bit_offset = bit_offset_of_field(next_ptr_loc, next)
    if bit_offset is None:
        print(
            message.error(
                f"{path}{sep}{next_ptr_name} has no known offset \
            from {deref}{path}{inner_sep}{inner_name}"
            )
        )
        return
    byte_offset = get_byte_offset(bit_offset)
    if byte_offset is None:
        print(
            message.error(
                f"{path}{sep}{next_ptr_name} is a non-whole \
            number of bytes {bit_offset} bits) offset from \
            {deref}{path}{inner_sep}{inner_name}"
            )
        )
        return
    next_offset = byte_offset

    # If the next pointer points to an intance of the inner structure, we will
    # additionally have to do the equivalent of container_of(next, typeof(first),
    # inner_name).
    #
    # Here, we figure out how many bytes to subtract from *typeof(inner) so that
    # we can have a *typeof(first).
    pointee_offset = 0
    if inner is not None and next_ptr.type.target() == inner.type:
        pointee_offset = inner_offset
    elif next_ptr.type.target() == first.type:
        # We've already got everything we need for this mode.
        pass
    else:
        print(
            message.error(
                f"{deref}{path}{sep}{next_ptr_name} has a \
            different type than {path}"
            )
        )
        return

    # Now, we follow the chain. We have to do this in two steps, as, because we
    # have the address of the first outer structure, in case pointee_offset is
    # not zero, the offset for the first element will not be the same as the one
    # for all of the elements after it.
    offset0 = inner_offset + next_offset
    offset1 = offset0 - pointee_offset

    total = offset + count

    if total >= 2:
        addresses = pwndbg.chain.get(int(first.address), limit=1, offset=offset0)
        if len(addresses) > 1 and total >= 3:
            addresses.extend(
                pwndbg.chain.get(addresses[1], offset=offset1, include_start=False, limit=total - 2)
            )
    else:
        addresses = [int(first.address)]

    # Finally, dump the information in the addresses we've just gathered.
    for i, address in enumerate(addresses):
        if i < offset:
            continue
        if address in (0, sentinel):
            break
        try:
            # Always make sure we have the address of the outer structure.
            if i > 0:
                address -= pointee_offset

            # Read the data and print it out.
            target_type = first.type
            target_address = address
            if field_offset is not None:
                target_type = field_type
                target_address = address + field_offset

            value = pwndbg.aglib.memory.get_typed_pointer_value(target_type, target_address)

            symbol = pwndbg.aglib.symbol.resolve_addr(target_address)
            symbol = f"<{symbol}>" if symbol else ""

            print(f"{target_address:#x} {symbol}: {value.value_to_human_readable()}")
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Cannot dereference {address:#x} for list link #{i + 1}: {e}"))
            print(message.error("Is the linked list corrupted or is the sentinel value wrong?"))
            return


# Helper functions to resolve the offsets of fields inside a structure.
def bit_offset_of_field(struct, field_name, inner_name=None):
    offset = None
    for field in struct.type.fields():
        if field.name == field_name:
            offset = field.bitpos
    return offset


def get_byte_offset(bit_offset):
    if bit_offset % 8 != 0:
        return None
    return bit_offset // 8
