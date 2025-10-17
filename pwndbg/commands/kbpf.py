from __future__ import annotations

import argparse
import math
import re

import capstone

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
parser.add_argument("-v", "--verbose", action="count", default=0)
parser.add_argument("-p", "--progs", dest="print_progs", action="store_true", default=False)
parser.add_argument("-m", "--maps", dest="print_maps", action="store_true", default=False)

_bpf_map_array_off = None
MAX_PRINTED_VALUE_SIZE = 0x20
MAX_BPF_VERBOSE_LEVEL1_OUTPUT_LEN = 0x10
BPF_FIRST_REG, BPF_SECOND_REG = 1 << 0, 1 << 1
BPF_AUX_REG_STRING = "ax"
BPF_MAP_ARRAY_TYPES = (
    "BPF_MAP_TYPE_ARRAY",
    "BPF_MAP_TYPE_PROG_ARRAY",
)


def handle_bpf_aux_reg_for_insns_bytes(insns_bytes):
    # https://elixir.bootlin.com/linux/v6.17.1/source/include/linux/filter.h#L62
    sz = len(insns_bytes)
    result = [0] * (len(insns_bytes) // 8)
    for i in range(1, sz, 8):
        b = insns_bytes[i]
        if b & 0xF == 0xB:
            result[i // 8] |= BPF_FIRST_REG
            insns_bytes[i] &= ~0xF
        if b & 0xF0 == 0xB0:
            result[i // 8] |= BPF_SECOND_REG
            insns_bytes[i] &= ~0xF0
    return result


def handle_bpf_aux_reg_for_opstr(opstr, regflag):
    if regflag == 0:
        return opstr
    pattern = re.compile(r"r0")
    matches = list(pattern.finditer(opstr))
    if regflag & BPF_FIRST_REG:
        start, end = matches[0].span()
        opstr = opstr[:start] + BPF_AUX_REG_STRING + opstr[end:]
    if regflag & BPF_SECOND_REG:
        start, end = matches[-1].span()
        opstr = opstr[:start] + BPF_AUX_REG_STRING + opstr[end:]
    return opstr


def bpf_map_array_offset(bpf_array, t, max_entries, value_size):
    global _bpf_map_array_off
    if _bpf_map_array_off:
        # pwndbg.lib.cache is not used here because it would also cache None
        return _bpf_map_array_off
    if t in BPF_MAP_ARRAY_TYPES:
        expected_elem_size = math.ceil(value_size / 8) * 8
        expected_index_mask = (1 << math.ceil(math.log2(max_entries))) - 1
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
                _bpf_map_array_off = (i + 2) * 4 + pwndbg.aglib.arch.ptrsize
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


def print_bpf_progs(verbose):
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
                if verbose > 0:
                    cs = capstone.Cs(
                        capstone.CS_ARCH_BPF,
                        capstone.CS_MODE_LITTLE_ENDIAN | capstone.CS_MODE_BPF_EXTENDED,
                    )
                    num_insns = int(bpf_prog["len"])
                    insns = int(bpf_prog["insns"].address)
                    insns_bytes = pwndbg.aglib.memory.read(insns, num_insns * 8)
                    aux_regs = handle_bpf_aux_reg_for_insns_bytes(insns_bytes)
                    with indent:
                        indent.print(indent.prefix(f"{num_insns} insns") + ":")
                        for i in range(num_insns):
                            if i == MAX_BPF_VERBOSE_LEVEL1_OUTPUT_LEN and verbose == 1:
                                indent.print("... (truncated)")
                                indent.print(
                                    M.warn("max output len reached, use -vv for full output")
                                )
                                break
                            off = i * 8
                            address = insns + off
                            disass = list(
                                cs.disasm(bytes(insns_bytes[off : off + 8]), insns + address)
                            )
                            if len(disass) == 0:
                                bytecode = ""
                                for b in insns_bytes[off : off + 8]:
                                    bytecode += f"{b:02x} "
                                desc = M.error(f"invalid insn: {bytecode}")
                                indent.print(f"{indent.addr_hex(address)}\t{desc}")
                                continue
                            insn = disass[0]
                            mnemonic = insn.mnemonic
                            opstr = insn.op_str
                            opstr = handle_bpf_aux_reg_for_opstr(opstr, aux_regs[i])
                            indent.print(f"{indent.addr_hex(address)}\t{mnemonic}\t{opstr}")


def print_bpf_maps(verbose):
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
                off = bpf_map_array_offset(bpf_array, t, max_entries, value_size)
                content = indent.aux_hex(bpf_array + off) if off else "unknown"
                desc = f"array @ {content} (key_size: {indent.aux_hex(key_size)}, value_size: {indent.aux_hex(value_size)}, max_entries: {indent.aux_hex(max_entries)})"
                indent.print(desc)
                # TODO: what about types other than array
                if off is not None and verbose > 0 and t in BPF_MAP_ARRAY_TYPES:
                    with indent:
                        entrysz = math.ceil(value_size / 8) * 8
                        for i in range(max_entries):
                            if i == MAX_BPF_VERBOSE_LEVEL1_OUTPUT_LEN and verbose == 1:
                                indent.print("... (truncated)")
                                indent.print(
                                    M.warn("max output len reached, use -vv for full output")
                                )
                                break
                            idxfmt = f"[0x{i:02x}]"
                            sz = min(value_size, MAX_PRINTED_VALUE_SIZE)
                            value = ""
                            for b in pwndbg.aglib.memory.read(bpf_array + off + i * entrysz, sz):
                                value += f"{b:02x} "
                            if sz < value_size:
                                value += "... (" + M.warn("truncated") + ")"
                            indent.print(f"- {indent.prefix(idxfmt)} {value}")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def kbpf(verbose: int, print_progs: bool, print_maps: bool):
    if not pwndbg.aglib.kernel.has_debug_info():
        pwndbg.aglib.kernel.bpf.load_bpf_typeinfo()
    if pwndbg.aglib.typeinfo.load("struct idr") is None:
        return
    if not print_progs and not print_maps:
        print_progs = print_maps = True
    if print_progs:
        print_bpf_progs(verbose)
    if print_maps:
        print_bpf_maps(verbose)
