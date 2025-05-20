from __future__ import annotations

import argparse
import logging
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.color as C
import pwndbg.commands
import pwndbg.dbg
from pwndbg.aglib.kernel.macros import container_of
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.aglib.kernel.rbtree import for_each_rb_entry
from pwndbg.commands import CommandCategory

log = logging.getLogger(__name__)

addrc = C.green
fieldnamec = C.blue
fieldvaluec = C.yellow
typenamec = C.red


def for_each_transaction(addr: pwndbg.dbg_mod.Value, field: str) -> Iterator[pwndbg.dbg_mod.Value]:
    typename = "struct binder_transaction"
    addr_int = int(addr)
    while addr_int != 0:
        transaction = pwndbg.aglib.memory.get_typed_pointer(typename, addr)
        yield transaction

        addr = transaction[field]
        addr_int = int(addr)


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


# TODO: merge with for_each_entry?
def for_each_hlist_entry(
    head: pwndbg.dbg_mod.Value, typename, field
) -> Iterator[pwndbg.dbg_mod.Value]:
    addr = head["first"]
    addr_int = int(addr)
    while addr_int != 0:
        yield container_of(addr_int, typename, field)
        addr = addr.dereference()["next"]
        addr_int = int(addr)


class BinderVisitor:
    def __init__(self, procs_addr):
        self.indent = IndentContextManager()
        self.addr = pwndbg.aglib.memory.get_typed_pointer_value("struct hlist_head", procs_addr)

    def _format_indent(self, text: str) -> str:
        return "    " * self.indent.indent + text

    def _format_heading(self, typename: str, fields: str, addr: int) -> str:
        hex_addr = hex(addr)
        return self._format_indent(
            f"{fieldnamec(typename)} {fieldvaluec(fields)} ({addrc(hex_addr)})"
        )

    # TODO: do this in a cleaner, object-oriented way
    def _format_field(
        self,
        field: Optional[str] = None,
        value: pwndbg.dbg_mod.Value | str = "",
        only_heading: bool = True,
    ) -> str:
        if isinstance(value, pwndbg.dbg_mod.Value):
            t = value.type
            if t.code == pwndbg.dbg_mod.TypeCode.TYPEDEF:
                real_type = t.strip_typedefs()

                # We only want to replace the typedef with the real type if the
                # real type is not an anonymous struct
                if real_type.name_identifier:
                    t = real_type

            if t.code == pwndbg.dbg_mod.TypeCode.INT:
                value = int(value)
            elif t.code == pwndbg.dbg_mod.TypeCode.BOOL:
                value = True if int(value) else False
            elif t.code == pwndbg.dbg_mod.TypeCode.POINTER:
                typename = t.target().name_identifier
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
            elif t.code in (pwndbg.dbg_mod.TypeCode.STRUCT, pwndbg.dbg_mod.TypeCode.TYPEDEF):
                typename = t.name_identifier
                if typename == "spinlock":
                    value = self.format_spinlock(value).strip()
                elif typename == "atomic_t":
                    value = value["counter"].value_to_human_readable()
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
        output += fieldvaluec(str(value))

        return self._format_indent(output)

    def format_rb_tree(self, field: str, value: pwndbg.dbg_mod.Value) -> Tuple[str, int]:
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

    def format_list(
        self, field: str, value: pwndbg.dbg_mod.Value, typename: str
    ) -> Tuple[str, int]:
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

    def _format_fields(
        self, obj: pwndbg.dbg_mod.Value, fields: List[str], only_heading: bool = True
    ) -> str:
        res = []
        for field in fields:
            res.append(self._format_field(field, obj[field], only_heading=only_heading))
        return "\n".join(res)

    def visit(self):
        for proc in for_each_hlist_entry(self.addr, "struct binder_proc", "proc_node"):
            print(self.format_proc(proc))
            print()

    def format_proc(self, proc: pwndbg.dbg_mod.Value, only_heading=False):
        res = []
        res.append(
            self._format_heading(
                "binder_proc", "PID %s" % proc["pid"].value_to_human_readable(), int(proc)
            )
        )

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

    def format_thread(self, thread: pwndbg.dbg_mod.Value, only_heading: bool = False) -> str:
        res = []
        res.append(
            self._format_heading(
                "binder_thread", "PID %s" % thread["pid"].value_to_human_readable(), int(thread)
            )
        )

        if only_heading:
            return "\n".join(res)

        with self.indent:
            fields = ["tmp_ref", "looper_need_return", "process_todo", "is_dead", "todo"]
            res.append(self._format_fields(thread, fields))

            # We need to print this separately since we wanted print the entire
            # object and not just the heading
            res.append(self._format_fields(thread, ["transaction_stack"], only_heading=False))

        return "\n".join(res)

    def format_transaction(
        self, transaction: pwndbg.dbg_mod.Value, only_heading: bool = False
    ) -> str:
        res = []
        res.append(
            self._format_heading(
                "binder_transaction",
                "ID %s" % transaction["debug_id"].value_to_human_readable(),
                int(transaction),
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

    def format_node(self, node: pwndbg.dbg_mod.Value) -> str:
        res = []
        res.append(self._format_heading("binder_node", "", int(node)))
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

    def format_ref(self, ref: pwndbg.dbg_mod.Value, only_heading: bool = False) -> str:
        res = []
        res.append(
            self._format_heading(
                "binder_ref", "HANDLE %s" % ref["data"]["desc"].value_to_human_readable(), int(ref)
            )
        )

        if only_heading:
            return "\n".join(res)

        with self.indent:
            fields = ["strong", "weak"]
            res.append(self._format_fields(ref["data"], fields))

        return "\n".join(res)

    def format_work(self, work: pwndbg.dbg_mod.Value) -> str:
        res = []
        res.append(
            self._format_heading(
                "binder_work", work["type"].value_to_human_readable(), int(work.address)
            )
        )

        t = int(work["type"])
        # TODO: Create enum
        if t == 1:
            obj = container_of(int(work.address), "struct binder_transaction", "work")
        elif t in [2, 3]:
            return "\n".join(res)  # These are just binder_work objects
        elif t == 4:
            obj = container_of(int(work.address), "struct binder_error", "work")
        elif t == 5:
            obj = container_of(int(work.address), "struct binder_node", "work")
        elif t in [6, 7, 8]:
            obj = container_of(int(work.address), "struct binder_ref_death", "work")
        else:
            assert False

        with self.indent:
            res.append(self._format_field(value=obj))

        return "\n".join(res)

    def print_object(self, obj: pwndbg.dbg_mod.Value):
        # TODO: type
        print(obj)

    def format_spinlock(self, lock: pwndbg.dbg_mod.Value) -> str:
        raw_lock = lock["rlock"]["raw_lock"]
        val = pwndbg.aglib.memory.ushort(int(raw_lock.address))
        locked = val & 0xFF
        pending = val >> 8

        return self._format_heading("", f"LOCKED: {locked} PENDING: {pending}", int(lock.address))


parser = argparse.ArgumentParser(description="Show Android Binder information")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def binder():
    log.warning("This command is a work in progress and may not work as expected.")
    procs_addr = pwndbg.aglib.symbol.lookup_symbol_addr("binder_procs")
    assert procs_addr is not None, "Symbol binder_procs not exists"

    bv = BinderVisitor(procs_addr)
    bv.visit()
