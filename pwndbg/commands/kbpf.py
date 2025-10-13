from __future__ import annotations

import argparse
import math

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.bpf
import pwndbg.aglib.memory
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

parser = argparse.ArgumentParser(
    description="Prints information about the linux kernel bpf progs and maps."
)

_bpf_map_array_off = None
BPF_MAP_ARRAY_TYPES = (
    "ARRAY",
    "PROG_ARRAY",
)


def bpf_map_array_offset(bpf_array, t, key_size, value_size):
    global _bpf_map_array_off
    if _bpf_map_array_off:
        # pwndbg.lib.cache is not used here because it would also cache None
        return _bpf_map_array_off
    if any(t.endswith(sub) for sub in BPF_MAP_ARRAY_TYPES):
        expected_elem_size = math.ceil(value_size / 8) * 8
        expected_index_mask = (1 << key_size) - 1
        for i in range(200):
            elem_size = pwndbg.aglib.memory.u32(bpf_array + 4 * i)
            index_mask = pwndbg.aglib.memory.u32(bpf_array + 4 * (i + 1))
            if elem_size == expected_elem_size and index_mask == expected_index_mask:
                """
                struct bpf_array {
                    struct bpf_map map;
                    u32 elem_size; // i points here
                    u32 index_mask;
                    struct bpf_array_aux *aux;
                    union {
                        DECLARE_FLEX_ARRAY(char, value) __aligned(8);
                        DECLARE_FLEX_ARRAY(void *, ptrs) __aligned(8);
                        DECLARE_FLEX_ARRAY(void __percpu *, pptrs) __aligned(8);
                    };
                };
                """
                _bpf_map_array_off = (i + 2) * 4
                break
    return _bpf_map_array_off


def parse_xa_node(xa_node):
    xa_node = int(xa_node) & ~3
    if xa_node == 0 or not pwndbg.aglib.memory.is_kernel(xa_node):
        return []
    xa_node = pwndbg.aglib.memory.get_typed_pointer("struct xa_node", xa_node)
    result = []
    shift = int(xa_node["shift"])
    count = int(xa_node["count"])
    for i in range(64):
        slot = int(xa_node["slots"][i])
        if slot == 0:
            continue
        if shift:
            result += parse_xa_node(slot)
        else:
            result.append(slot)
        count -= 1
        if count == 0:
            break
    return result


def print_bpf_progs():
    indent = IndentContextManager()
    prog_idr = pwndbg.aglib.kernel.prog_idr()
    if int(prog_idr) == 0:
        print(M.warn("cannot find prog_idr"))
        return
    prog_idr = pwndbg.aglib.memory.get_typed_pointer("struct idr", prog_idr)
    xa_node = prog_idr["idr_rt"]["xa_head"]
    indent.print(indent.prefix("bpf progs") + f": prog_idr @ {indent.addr_hex(int(prog_idr))}")
    if int(xa_node) == 0:
        return
    slots = parse_xa_node(xa_node)
    with indent:
        for idx, slot in enumerate(slots):
            bpf_prog = pwndbg.aglib.memory.get_typed_pointer("struct bpf_prog", slot)
            t = bpf_prog["type"].value_to_human_readable()
            attach_t = bpf_prog["expected_attach_type"].value_to_human_readable()
            prefix = indent.prefix(f"[0x{idx:02x}] {indent.addr_hex(slot)}")
            indent.print(f"{prefix} (type: {M.success(t)}, attach: {M.success(attach_t)})")
            with indent:
                func = int(bpf_prog["bpf_func"])
                aux = int(bpf_prog["aux"])
                jited_len = int(bpf_prog["jited_len"])
                desc = f"func @ {indent.aux_hex(func)} (jited_len: {indent.aux_hex(jited_len)}), aux @ {indent.aux_hex(aux)}"
                indent.print(desc)


def print_bpf_maps():
    indent = IndentContextManager()
    map_idr = pwndbg.aglib.kernel.map_idr()
    if int(map_idr) == 0:
        print(M.warn("cannot find map_idr"))
        return
    map_idr = pwndbg.aglib.memory.get_typed_pointer("struct idr", map_idr)
    xa_node = map_idr["idr_rt"]["xa_head"]
    if int(xa_node) == 0:
        return
    indent.print(indent.prefix("bpf maps") + f": map_idr @ {indent.addr_hex(int(map_idr))}")
    slots = parse_xa_node(xa_node)
    with indent:
        for idx, slot in enumerate(slots):
            bpf_array = pwndbg.aglib.memory.get_typed_pointer("struct bpf_array", slot)
            prefix = indent.prefix(f"[0x{idx:02x}] {indent.addr_hex(slot)}")
            t = bpf_array["map"]["map_type"].value_to_human_readable()
            indent.print(f"{prefix} (type: {M.success(t)})")
            with indent:
                key_size = int(bpf_array["map"]["key_size"])
                value_size = int(bpf_array["map"]["value_size"])
                max_entries = int(bpf_array["map"]["max_entries"])
                bpf_array = int(bpf_array)
                off = bpf_map_array_offset(bpf_array, t, key_size, value_size)
                content = indent.aux_hex(bpf_array + off) if off else "unknown"
                desc = f"array @ {content} (key_size: {indent.aux_hex(key_size)}, value_size: {indent.aux_hex(value_size)}, max_entries: {indent.aux_hex(max_entries)})"
                indent.print(desc)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def kbpf():
    if not pwndbg.aglib.kernel.has_debug_info():
        pwndbg.aglib.kernel.bpf.load_bpf_typeinfo()
    if pwndbg.aglib.typeinfo.load("struct idr") is None:
        return
    print_bpf_progs()
    print_bpf_maps()
