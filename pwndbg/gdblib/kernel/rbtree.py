from __future__ import annotations

import gdb

from pwndbg.gdblib.events import new_objfile
from pwndbg.gdblib.kernel.macros import container_of

rb_root_type = None
rb_node_type = None


@new_objfile
def init():
    global rb_root_type, rb_node_type
    try:
        rb_root_type = gdb.lookup_type("struct rb_root")
        rb_node_type = gdb.lookup_type("struct rb_node")
    except Exception:
        pass


def for_each_rb_entry(root, typename, fieldname):
    node = rb_first(root)
    while node is not None and node != 0:
        yield container_of(node, typename, fieldname)
        node = rb_next(node)


def rb_first(root):
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise gdb.GdbError("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if node == 0:
        return None

    while node["rb_left"]:
        node = node["rb_left"]

    return node


def rb_last(root):
    if root.type == rb_root_type:
        node = root.address.cast(rb_root_type.pointer())
    elif root.type != rb_root_type.pointer():
        raise gdb.GdbError("Must be struct rb_root not {}".format(root.type))

    node = root["rb_node"]
    if node == 0:
        return None

    while node["rb_right"]:
        node = node["rb_right"]

    return node


def rb_parent(node):
    parent = gdb.Value(node["__rb_parent_color"] & ~3)
    return parent.cast(rb_node_type.pointer())


def rb_empty_node(node):
    return node["__rb_parent_color"] == node.address


def rb_next(node):
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise gdb.GdbError("Must be struct rb_node not {}".format(node.type))

    if rb_empty_node(node):
        return None

    if node["rb_right"]:
        node = node["rb_right"]
        while node["rb_left"]:
            node = node["rb_left"]
        return node

    parent = rb_parent(node)
    while parent and node == parent["rb_right"]:
        node = parent
        parent = rb_parent(node)

    return parent


def rb_prev(node):
    if node.type == rb_node_type:
        node = node.address.cast(rb_node_type.pointer())
    elif node.type != rb_node_type.pointer():
        raise gdb.GdbError("Must be struct rb_node not {}".format(node.type))

    if rb_empty_node(node):
        return None

    if node["rb_left"]:
        node = node["rb_left"]
        while node["rb_right"]:
            node = node["rb_right"]
        return node.dereference()

    parent = rb_parent(node)
    while parent and node == parent["rb_left"].dereference():
        node = parent
        parent = rb_parent(node)

    return parent
