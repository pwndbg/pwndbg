from __future__ import annotations

from typing import Iterator

import gdb

import pwndbg
from pwndbg.dbg import EventType
from pwndbg.gdblib.kernel.macros import container_of

rb_root_type: gdb.Type = None
rb_node_type: gdb.Type = None


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def init():
    global rb_root_type, rb_node_type
    try:
        rb_root_type = gdb.lookup_type("struct rb_root")
        rb_node_type = gdb.lookup_type("struct rb_node")
    except Exception:
        pass


def for_each_rb_entry(root: gdb.Value, typename: str, fieldname: str) -> Iterator[gdb.Value]:
    node = rb_first(root)
    node_addr = int(node or 0)
    while node_addr != 0:
        yield container_of(node_addr, typename, fieldname)
        node = rb_next(node)
        node_addr = int(node or 0)


def rb_first(root: gdb.Value) -> gdb.Value | None:
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise gdb.GdbError("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if int(node) == 0:
        return None

    while int(node["rb_left"]):
        node = node["rb_left"]

    return node


def rb_last(root: gdb.Value) -> gdb.Value | None:
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise gdb.GdbError("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if int(node) == 0:
        return None

    while int(node["rb_right"]):
        node = node["rb_right"]

    return node


def rb_parent(node: gdb.Value) -> gdb.Value:
    parent = gdb.Value(int(node["__rb_parent_color"]) & ~3)
    return parent.cast(rb_node_type.pointer())


def rb_empty_node(node: gdb.Value) -> bool:
    return int(node["__rb_parent_color"]) == int(node.address)


def rb_next(node: gdb.Value) -> gdb.Value | None:
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise gdb.GdbError("Must be struct rb_node not {}".format(node.type))

    if rb_empty_node(node):
        return None

    if int(node["rb_right"]):
        node = node["rb_right"]
        while int(node["rb_left"]):
            node = node["rb_left"]
        return node

    parent = rb_parent(node)
    while int(parent) and int(node) == int(parent["rb_right"]):
        node = parent
        parent = rb_parent(node)

    return parent


def rb_prev(node: gdb.Value) -> gdb.Value | None:
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise gdb.GdbError("Must be struct rb_node not {}".format(node.type))

    if rb_empty_node(node):
        return None

    if int(node["rb_left"]):
        node = node["rb_left"]
        while int(node["rb_right"]):
            node = node["rb_right"]
        return node.dereference()

    parent = rb_parent(node)
    while int(parent) and int(node) == int(parent["rb_left"].dereference()):
        node = parent
        parent = rb_parent(node)

    return parent
