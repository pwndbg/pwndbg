from __future__ import annotations

import pwndbg.aglib.symbol

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.BIONIC


def verify_libc_candidate(mapping_name: str) -> bool:
    """
    android_reset_stack_guards exists since API 31 (Android 12, 2021)

    https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/bionic/__libc_init_main_thread.cpp
    https://android.googlesource.com/platform/bionic/+/master/libc/libc.map.txt
    """
    return (
        pwndbg.aglib.symbol.lookup_symbol(
            "android_reset_stack_guards", objfile_endswith=mapping_name
        )
        is not None
    )


def version(libc_filepath: str) -> tuple[int, ...]:
    """
    Each symbol and the respective introduced API level can be read in:

    https://android.googlesource.com/platform/bionic/+/master/libc/libc.map.txt
    """
    api_symbols = [
        (37, "sched_getattr"),  # Android 17
        (36, "lchmod"),  # Android 16
        (35, "android_crash_detail_register"),  # Android 15
        (34, "close_range"),  # Android 14
        (33, "backtrace"),  # Android 13
        (31, "android_reset_stack_guards"),  # Android 12
        (29, "android_get_device_api_level"),  # Android 10
        (28, "__ppoll64_chk"),  # Android 9
        (26, "catclose"),  # Android 8.0
        (24, "preadv"),  # Android 7.0
        (23, "error_at_line"),  # Android 6.0
        (21, "epoll_create1"),  # Android 5.0
    ]
    for api_level, api_symbol in api_symbols:
        if (
            pwndbg.aglib.symbol.lookup_symbol(api_symbol, objfile_endswith=libc_filepath)
            is not None
        ):
            return (api_level,)

    return (-1, -1)


def has_internal_symbols(libc_filepath: str) -> bool:
    return (
        # __libc_globals in present since Android 7.0 (API 24)
        pwndbg.aglib.symbol.lookup_symbol("__libc_globals", objfile_endswith=libc_filepath)
        is not None
    )


def has_debug_info() -> bool:
    # scudo::Chunk::UnpackedHeader is present since Android 11 (API 30)
    return pwndbg.aglib.typeinfo.load("scudo::Chunk::UnpackedHeader") is not None


def urls(ver: tuple[int, ...] | None) -> LibcURLs:
    readable_source = "https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc"

    if ver is not None and ver[0] > 0:
        api_level = ver[0]

        api_branch = {
            36: "android15-release",
            35: "android15-release",
            34: "android14-release",
            33: "android13-release",
            31: "android12-release",
            30: "android11-release",
            29: "android10-release",
        }

        branch = api_branch.get(api_level, "main")
        readable_source = (
            f"https://android.googlesource.com/platform/bionic/+/refs/heads/{branch}/libc"
        )

    return LibcURLs(
        versioned_readable_source=readable_source,
        versioned_compressed_source="https://android.googlesource.com/platform/bionic/+archive/refs/heads/main.tar.gz",
        homepage="https://android.googlesource.com/platform/bionic/",
        git="https://android.googlesource.com/platform/bionic.git",
    )


def verify_ld_candidate(mapping_name: str) -> bool:
    return False


def libc_same_as_ld() -> bool:
    return False
