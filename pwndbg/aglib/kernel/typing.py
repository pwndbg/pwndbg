from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TypeVar

from typing_extensions import ParamSpec

import pwndbg.aglib.kernel
import pwndbg.aglib.structures
import pwndbg.aglib.typeinfo
from pwndbg.lib import Status
from pwndbg.lib import TypeNotFoundError
from pwndbg.lib import TypeNotRecoveredError

COMMON_TYPES = """
#include <stdint.h>
#include <stddef.h>
#include <linux/version.h>
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long u64;
#define bool int
#if UINTPTR_MAX == 0xffffffff
    typedef int16_t arch_word_t;
#else
    typedef int32_t arch_word_t;
#endif
typedef struct {
    unsigned int val;
} kuid_t;
typedef struct {
    unsigned int val;
} kgid_t;
typedef int pid_t;
typedef struct {
    int counter;
} atomic_t;
typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;
typedef struct {
	unsigned long f;
} memdesc_flags_t;

struct list_head {
    struct list_head *next, *prev;
};
struct hlist_node {
	struct hlist_node *next, **pprev;
};
struct kmem_cache;
enum pageflags {
	PG_locked,		/* Page is locked. Don't touch. */
	PG_writeback,		/* Page is under writeback */
	PG_referenced,
	PG_uptodate,
	PG_dirty,
	PG_lru,
	PG_head,		/* Must be in bit 6 */
	PG_waiters,		/* Page has waiters, check its waitqueue. Must be bit #7 and in the same byte as "PG_locked" */
	PG_active,
	PG_workingset,
	PG_owner_priv_1,	/* Owner use. If pagecache, fs may use */
	PG_owner_2,		/* Owner use. If pagecache, fs may use */
	PG_arch_1,
	PG_reserved,
	PG_private,		/* If pagecache, has fs-private data */
	PG_private_2,		/* If pagecache, has fs aux data */
	PG_reclaim,		/* To be reclaimed asap */
	PG_swapbacked,		/* Page is backed by RAM/swap */
	PG_unevictable,		/* Page is "unevictable"  */
	PG_dropbehind,		/* drop pages on IO completion */
};
#define POINTER_SIZE (sizeof(void *))
"""


P = ParamSpec("P")
D = TypeVar("D")
T = TypeVar("T")


def typeinfo_recovery(
    name: str, requires_kversion: bool = False, requires_kbase: bool = False
) -> Callable[[Callable[P, str]], Callable[P, None]]:
    """
    Attached to functions which return the C source-code of the `name` type (usually struct).

    Compiles and adds the debug info for the struct into the debugger, from then on accessible via APIs
    like `pwndbg.aglib.memory.get_typed_pointer("struct list_head", db_list)`.
    """

    def decorator(f: Callable[P, str]) -> Callable[P, None]:
        # returns true if the type exists or has been successfully recovered
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> None:
            if not pwndbg.dbg.selected_inferior().is_linux():
                # make sure the target is linux, should we specify symbols instead?
                raise TypeNotRecoveredError(name, "target is not linux")
            if pwndbg.aglib.kernel.has_debug_info():
                return
            if pwndbg.aglib.typeinfo.lookup_types(name) is not None:
                return
            recover_common_types_func = recover_page_typeinfo
            if f.__name__ != recover_common_types_func.__name__:
                recover_common_types_func()
            if requires_kversion and pwndbg.aglib.kernel.kversion() is None:
                raise TypeNotRecoveredError(name, "kernel version is unavailable")
            if requires_kbase and pwndbg.aglib.kernel.paging.kbase is None:
                raise TypeNotRecoveredError(name, "kernel base not found")

            try:
                result = f(*args, **kwargs)
            except TypeNotFoundError as e:
                raise TypeNotRecoveredError(name, str(e))
            except AssertionError as e:
                # FIXME: Some type recovery functions `assert` under the assumption that the assert
                # will be caught here.
                raise TypeNotRecoveredError(name, str(e))

            fname = name.split()[-1] + "_structs"
            err: Status = pwndbg.aglib.structures.add(fname, result)
            if err.is_failure():
                raise TypeNotRecoveredError(name, err.message)
            return

        return func

    return decorator


@typeinfo_recovery("struct page", requires_kversion=True)
def recover_page_typeinfo() -> str:
    defs = []
    for config in (
        "CONFIG_MEMCG",
        "CONFIG_KASAN",
    ):
        if config in pwndbg.aglib.kernel.kconfig():
            defs.append(config)
    result = f"#define KVERSION {pwndbg.aglib.kernel.kversion_cint()}\n"
    result += "\n".join(f"#define {s}" for s in defs)
    result += COMMON_TYPES
    result += """
    struct page { // just a simplied page struct with relevant fields
#if KVERSION < KERNEL_VERSION(6, 18, 0)
        unsigned long flags;
#else
        memdesc_flags_t flags;
#endif
        union {
            struct {
                union {
                    struct {
                        union {
                            struct list_head lru;
                            struct list_head buddy_list;
                            struct list_head pcp_list;
                        };
                    };
                    struct {	/* Tail pages of compound page */
                        unsigned long compound_head;	/* Bit zero is set */
                    };
                };
            };
#if KVERSION < KERNEL_VERSION(5, 17, 0)
            struct {	/* slab, slob and slub */
                union {
                    struct list_head slab_list;
                    struct {	/* Partial pages */
                        struct page *next;
                        arch_word_t pages;	/* Nr of pages left */
#if KVERSION < KERNEL_VERSION(5, 16, 0)
                        arch_word_t pobjects;	/* Approximate count */
#endif
                    };
                };
                struct kmem_cache *slab_cache; /* not slob */
                /* Double-word boundary */
                void *freelist;		/* first free object */
                union {
                    void *s_mem;	/* slab: first object */
                    unsigned long counters;		/* SLUB */
                    struct {			/* SLUB */
                        unsigned inuse:16;
                        unsigned objects:15;
                        unsigned frozen:1;
                    };
                };
            };
#endif
            char _pad[0x28]; // the rest are not relavent to this project but needs to be 0x28 bytes
        };
        union {
            atomic_t _mapcount;
            unsigned int page_type;
        };
        atomic_t _refcount;
#ifdef CONFIG_MEMCG
        unsigned long memcg_data;
#endif
#if defined(WANT_PAGE_VIRTUAL) /* never set for x86 and arm */
        void *virtual;
#endif /* WANT_PAGE_VIRTUAL */
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS /* TODO: seems never got set for all the kernel builds I have worked with */
#if KVERSION >= KERNEL_VERSION(6, 7, 0)
        int _last_cpupid;
#endif
#endif
#if defined(CONFIG_KASAN) && KVERSION >= KERNEL_VERSION(6, 1, 0)
        struct page *kmsan_shadow;
        struct page *kmsan_origin;
#endif
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
#if KVERSION < KERNEL_VERSION(6, 7, 0)
        int _last_cpupid;
#endif
#endif
    };
    """
    return result
