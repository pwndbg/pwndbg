from __future__ import annotations

from typing import Iterator

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
from pwndbg.aglib.kernel.macros import container_of
from pwndbg.dbg import EventType

rb_root_type: pwndbg.dbg_mod.Type = None
rb_node_type: pwndbg.dbg_mod.Type = None


@pwndbg.dbg.event_handler(EventType.START)
def init():
    global rb_root_type, rb_node_type
    rb_root_type = pwndbg.aglib.typeinfo.load("struct rb_root")
    rb_node_type = pwndbg.aglib.typeinfo.load("struct rb_node")


def for_each_rb_entry(
    root: pwndbg.dbg_mod.Value, typename: str, fieldname: str
) -> Iterator[pwndbg.dbg_mod.Value]:
    node = rb_first(root)
    node_addr = int(node or 0)
    while node_addr != 0:
        yield container_of(node_addr, typename, fieldname)
        node = rb_next(node)
        node_addr = int(node or 0)


def rb_first(root: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value | None:
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise pwndbg.dbg_mod.Error("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if int(node) == 0:
        return None

    while int(node["rb_left"]):
        node = node["rb_left"]

    return node


def rb_last(root: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value | None:
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise pwndbg.dbg_mod.Error("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if int(node) == 0:
        return None

    while int(node["rb_right"]):
        node = node["rb_right"]

    return node


def rb_parent(node: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value:
    val = int(node["__rb_parent_color"]) & ~3
    return pwndbg.aglib.memory.get_typed_pointer(rb_node_type, val)


def rb_empty_node(node: pwndbg.dbg_mod.Value) -> bool:
    return int(node["__rb_parent_color"]) == int(node.address or 0)


def rb_next(node: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value | None:
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise pwndbg.dbg_mod.Error("Must be struct rb_node not {}".format(node.type))

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


def rb_prev(node: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value | None:
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise pwndbg.dbg_mod.Error("Must be struct rb_node not {}".format(node.type))

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
