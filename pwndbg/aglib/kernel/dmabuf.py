from __future__ import annotations

import pwndbg.aglib.kernel


def find_dmabuf_offsets(dmabuf) -> tuple[int, int, int]:
    MAX = 0x30
    sg_table_off, exp_name_off, list_node_off = None, None, None
    ptrsize = pwndbg.aglib.arch.ptrsize
    heap_buffer = pwndbg.aglib.memory.read_pointer_width(dmabuf + 2 * ptrsize)
    for i in range(1, MAX):
        # see recover_dmabuf_typeinfo (struct dma_buf) for an explanation
        # this loop is searching the `size` field from `list_node`
        size = pwndbg.aglib.memory.read_pointer_width(dmabuf - (i + 5) * ptrsize)
        file = pwndbg.aglib.memory.read_pointer_width(dmabuf - (i + 4) * ptrsize)
        attachments_prev = pwndbg.aglib.memory.read_pointer_width(dmabuf - (i + 3) * ptrsize)
        attachments_next = pwndbg.aglib.memory.read_pointer_width(dmabuf - (i + 2) * ptrsize)
        ops = pwndbg.aglib.memory.read_pointer_width(dmabuf - (i + 1) * ptrsize)
        vmapping_counter = pwndbg.aglib.memory.read_pointer_width(dmabuf - i * ptrsize)
        if pwndbg.aglib.memory.is_kernel(size):
            continue
        if not pwndbg.aglib.memory.is_kernel(file):
            continue
        if not (
            pwndbg.aglib.memory.is_kernel(attachments_next)
            and pwndbg.aglib.memory.is_kernel(attachments_prev)
        ):
            continue
        if not pwndbg.aglib.memory.is_kernel(ops):
            continue
        if pwndbg.aglib.memory.is_kernel(vmapping_counter):
            continue
        # (i + 5) * ptrsize is the distance from the `size` to `list_node`
        list_node_off = (i + 5) * ptrsize
        break
    assert list_node_off is not None, "cannot determine the offset of list_node"
    dmabuf -= list_node_off
    for i in range(5, MAX):
        ptr = pwndbg.aglib.memory.read_pointer_width(dmabuf + i * ptrsize)
        try:
            if len(pwndbg.aglib.memory.string(ptr).decode()) == 0:
                continue
        except Exception:
            continue
        exp_name_off = i * ptrsize
        break
    assert exp_name_off is not None, "cannot determine the offset of exp_name"
    sz = pwndbg.aglib.memory.read_pointer_width(dmabuf)
    for i in range(MAX):
        if pwndbg.aglib.memory.read_pointer_width(heap_buffer + i * ptrsize) == sz:
            sg_table_off = (i + 1) * ptrsize
            break
    assert sg_table_off is not None, "cannot determine the offset of sg_table"
    return sg_table_off, exp_name_off, list_node_off


@pwndbg.aglib.kernel.typeinfo_recovery("struct dma_buf")
def recover_dmabuf_typeinfo(first_dmabuf: int) -> str:
    # reaching here means priv exists
    sg_table_off, exp_name_off, list_node_off = find_dmabuf_offsets(first_dmabuf)
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += f"""
    typedef unsigned long dma_addr_t;
    struct scatterlist {{
        unsigned long	page_link; // either to a page or scatterlist
        unsigned int	offset;
        unsigned int	length;
        dma_addr_t	dma_address;
    /*** potentially has 8 more bytes
#ifdef CONFIG_NEED_SG_DMA_LENGTH
        unsigned int	dma_length;
#endif
#ifdef CONFIG_NEED_SG_DMA_FLAGS
        unsigned int    dma_flags;
#endif
    ***/
    }};
    struct sg_table {{
        struct scatterlist *sgl;	/* the list */
        unsigned int nents;		/* number of mapped entries */
        unsigned int orig_nents;	/* original size of list */
    }};
    struct system_heap_buffer {{
        char _pad[{sg_table_off}];
        struct sg_table sg_table;
        /* rest of the fields are irrelevant */
    }};
    struct dma_buf {{
        size_t size; // (i + 5) is here
        void *file;
        struct list_head attachments;
        void *ops; // const struct dma_buf_ops *
        unsigned vmapping_counter;
        char _pad1[{exp_name_off - pwndbg.aglib.arch.ptrsize * 6}];
        const char *exp_name;
        const char *name;
        char _pad2[{list_node_off - exp_name_off - pwndbg.aglib.arch.ptrsize * 2}];
        struct list_head list_node;
        struct system_heap_buffer *priv; // treating the voidptr as system_heap_buffer
        /* rest of the fields are irrelevant */
    }};
    """
    return result
