from __future__ import annotations

import argparse
import logging
from typing import Any
from typing import Optional

import gdb

import pwndbg.color as C
import pwndbg.commands
import pwndbg.gdblib.symbol
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.kernel.macros import container_of
from pwndbg.gdblib.kernel.macros import for_each_entry
from pwndbg.gdblib.kernel.rbtree import for_each_rb_entry

log = logging.getLogger(__name__)

addrc = C.green
fieldnamec = C.blue
fieldvaluec = C.yellow
typenamec = C.red


def for_each_transaction(addr, field):
    typename = "struct binder_transaction"

    while addr != 0:
        transaction = gdb.Value(addr).cast(gdb.lookup_type(typename).pointer())
        yield transaction

        addr = transaction[field]


# TODO: pull this out from the slab command so we can reuse it
class IndentContextManager:
    def __init__(self):
        self.indent = 0

    def __enter__(self):
        self.indent += 1

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.indent -= 1
        assert self.indent >= 0


node_types = {
    "waiting_threads": "struct binder_thread",
    "todo": "struct binder_work",
    "refs": "struct binder_ref",
    "threads": "struct binder_thread",
    "nodes": "struct binder_node",
    "refs_by_node": "struct binder_ref",
}

entry_field_names = {
    "waiting_threads": "waiting_thread_node",
    "todo": "entry",
    "refs": "node_entry",
}

rb_node_field_names = {
    "threads": "rb_node",
    "nodes": "rb_node",
    "refs_by_node": "rb_node_node",
}

codenames = [x for x in dir(gdb) if "TYPE_CODE_" in x]
code_to_name = {getattr(gdb, name): name for name in codenames}
name_to_code = {v: k for k, v in code_to_name.items()}


# TODO: merge with for_each_entry?
def for_each_hlist_entry(head, typename, field):
    addr = head["first"]
    while addr != 0:
        yield container_of(addr, typename, field)
        addr = addr.dereference()["next"]


class BinderVisitor:
    def __init__(self, procs_addr):
        self.indent = IndentContextManager()
        self.addr = pwndbg.gdblib.memory.get_typed_pointer_value(
            gdb.lookup_type("struct hlist_head"), procs_addr
        )

    def _format_indent(self, text: str) -> str:
        return "    " * self.indent.indent + text

    def _format_heading(self, typename: str, fields, addr: int):
        hex_addr = hex(int(addr))
        return self._format_indent(
            f"{fieldnamec(typename)} {fieldvaluec(fields)} ({addrc(hex_addr)})"
        )

    # TODO: do this in a cleaner, object-oriented way
    def _format_field(self, field: Optional[str] = None, value: Any = "", only_heading=True):
        if isinstance(value, gdb.Value):
            t = value.type
            if t.code == name_to_code["TYPE_CODE_TYPEDEF"]:
                real_type = t.strip_typedefs()

                # We only want to replace the typedef with the real type if the
                # real type is not an anonymous struct
                if real_type.name is not None:
                    t = real_type

            if t.code == name_to_code["TYPE_CODE_INT"]:
                value = int(value)
            elif t.code == name_to_code["TYPE_CODE_BOOL"]:
                value = True if value else False
            elif t.code == name_to_code["TYPE_CODE_PTR"]:
                typename = t.target().name
                if int(value) == 0:
                    value = "NULL"
                elif typename == "binder_proc":
                    value = self.format_proc(value, only_heading=only_heading).strip()
                elif typename == "binder_thread":
                    value = self.format_thread(value, only_heading=only_heading).strip()
                elif typename == "binder_node":
                    value = self.format_node(value).strip()
                elif typename == "binder_ref":
                    value = self.format_ref(value, only_heading=only_heading).strip()
                elif typename == "binder_work":
                    value = self.format_work(value.dereference()).strip()
                elif typename == "binder_transaction":
                    value = self.format_transaction(value, only_heading=only_heading)
                    if only_heading:
                        value = value.strip()
                    else:
                        value = "\n" + "\n".join(["    " + line for line in value.split("\n")])
                else:
                    print(f"Warning: no formatter for pointer type {typename}")
            elif t.code in [name_to_code["TYPE_CODE_STRUCT"], name_to_code["TYPE_CODE_TYPEDEF"]]:
                typename = t.name
                if typename == "spinlock":
                    value = self.format_spinlock(value).strip()
                elif typename == "atomic_t":
                    value = value["counter"]
                elif typename == "rb_root":
                    assert field is not None
                    value, num_elts = self.format_rb_tree(field, value)
                    field += f" [{num_elts}]"
                elif typename in ["list_head", "hlist_head"]:
                    assert field is not None
                    value, num_elts = self.format_list(field, value, typename)
                    field += f" [{num_elts}]"
                else:
                    print(f"Warning: no formatter for type {typename}")
                    print(t)
            else:
                print(f"Warning: no formatter for type code {t.code}")

        output = ""
        if field:
            output += fieldnamec(field) + ": "
        output += fieldvaluec(value)

        return self._format_indent(output)

    def format_rb_tree(self, field, value):
        res = []

        node_type = node_types[field]
        entry_field_name = rb_node_field_names[field]

        with self.indent:
            for entry in for_each_rb_entry(
                value,
                node_type,
                entry_field_name,
            ):
                s = self._format_field(value=entry, only_heading=False)
                num_space = len(s) - len(s.lstrip())
                res.append(" " * num_space + "* " + s.lstrip())

        if len(res) == 0:
            return "EMPTY", 0

        # Prepend a newline so the list starts on the line after the field name
        return "\n" + "\n".join(res), len(res)

    def format_list(self, field, value, typename):
        res = []

        node_type = node_types[field]
        entry_field_name = entry_field_names[field]

        if typename == "list_head":
            each_entry = for_each_entry
        elif typename == "hlist_head":
            each_entry = for_each_hlist_entry
        else:
            assert False

        with self.indent:
            for entry in each_entry(
                value,
                node_type,
                entry_field_name,
            ):
                s = self._format_field(value=entry)
                num_space = len(s) - len(s.lstrip())
                res.append(" " * num_space + "* " + s.lstrip())

        if len(res) == 0:
            return "EMPTY", 0

        # Prepend a newline so the list starts on the line after the field name
        return "\n" + "\n".join(res), len(res)

    def _format_fields(self, obj, fields, only_heading=True):
        res = []
        for field in fields:
            res.append(self._format_field(field, obj[field], only_heading=only_heading))
        return "\n".join(res)

    def visit(self):
        for proc in for_each_hlist_entry(self.addr, "struct binder_proc", "proc_node"):
            print(self.format_proc(proc))
            print()

    def format_proc(self, proc, only_heading=False):
        res = []
        res.append(self._format_heading("binder_proc", "PID %s" % proc["pid"], proc))

        if only_heading:
            return "\n".join(res)

        with self.indent:
            fields = [
                "is_dead",
                "tmp_ref",
                "inner_lock",
                "outer_lock",
                "waiting_threads",
                "todo",
                "threads",
                "nodes",
                "refs_by_node",
            ]
            res.append(self._format_fields(proc, fields))

        return "\n".join(res)

    def format_thread(self, thread, only_heading=False):
        res = []
        res.append(self._format_heading("binder_thread", "PID %s" % thread["pid"], thread))

        if only_heading:
            return "\n".join(res)

        with self.indent:
            fields = ["tmp_ref", "looper_need_return", "process_todo", "is_dead", "todo"]
            res.append(self._format_fields(thread, fields))

            # We need to print this separately since we wanted print the entire
            # object and not just the heading
            res.append(self._format_fields(thread, ["transaction_stack"], only_heading=False))

        return "\n".join(res)

    def format_transaction(self, transaction, only_heading=False):
        res = []
        res.append(
            self._format_heading(
                "binder_transaction", "ID %d" % transaction["debug_id"], transaction
            )
        )

        if only_heading:
            return "\n".join(res)

        with self.indent:
            res.append(self._format_fields(transaction, ["lock", "to_proc", "from", "to_thread"]))

            if int(transaction["from_parent"]) == 0:
                res.append(self._format_field("from_parent", "NULL"))
            else:
                res.append(self._format_field("from_parent"))
                with self.indent:
                    for transaction in for_each_transaction(
                        transaction["from_parent"], "from_parent"
                    ):
                        res.append(self.format_transaction(transaction))

            if int(transaction["to_parent"]) == 0:
                res.append(self._format_field("to_parent", "NULL"))
            else:
                res.append(self._format_field("to_parent"))
                with self.indent:
                    for transaction in for_each_transaction(transaction["to_parent"], "to_parent"):
                        res.append(self.format_transaction(transaction))

        return "\n".join(res)

    def format_node(self, node):
        res = []
        res.append(self._format_heading("binder_node", "", node))
        with self.indent:
            fields = [
                "lock",
                "internal_strong_refs",
                "local_weak_refs",
                "local_strong_refs",
                "tmp_refs",
                "refs",
            ]
            res.append(self._format_fields(node, fields))

        return "\n".join(res)

    def format_ref(self, ref, only_heading=False):
        res = []
        res.append(self._format_heading("binder_ref", "HANDLE %s" % ref["data"]["desc"], ref))

        if only_heading:
            return "\n".join(res)

        with self.indent:
            fields = ["strong", "weak"]
            res.append(self._format_fields(ref["data"], fields))

        return "\n".join(res)

    def format_work(self, work):
        res = []
        res.append(self._format_heading("binder_work", work["type"], work.address))

        t = int(work["type"])
        # TODO: Create enum
        if t == 1:
            obj = container_of(work.address, "struct binder_transaction", "work")
        elif t in [2, 3]:
            return "\n".join(res)  # These are just binder_work objects
        elif t == 4:
            obj = container_of(work.address, "struct binder_error", "work")
        elif t == 5:
            obj = container_of(work.address, "struct binder_node", "work")
        elif t in [6, 7, 8]:
            obj = container_of(work.address, "struct binder_ref_death", "work")
        else:
            assert False

        with self.indent:
            res.append(self._format_field(value=obj))

        return "\n".join(res)

    def print_object(self, obj):
        # TODO: type
        print(obj)

    def format_spinlock(self, lock: gdb.Value) -> str:
        raw_lock = lock["rlock"]["raw_lock"]
        val = pwndbg.gdblib.memory.ushort(int(raw_lock.address))
        locked = val & 0xFF
        pending = val >> 8

        return self._format_heading("", f"LOCKED: {locked} PENDING: {pending}", int(lock.address))


parser = argparse.ArgumentParser(description="Show Android Binder information")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def binder():
    log.warning("This command is a work in progress and may not work as expected.")
    procs_addr = pwndbg.gdblib.symbol.address("binder_procs")
    bv = BinderVisitor(procs_addr)
    bv.visit()
