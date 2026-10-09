from __future__ import annotations

# this module is called `errnum` instead of `errno` as we'd otherwise import ourselves (recursively)
import errno
import os

MAX_ERRNO = max(errno.errorcode)


def is_error(errno: int, ptrbits: int) -> tuple[bool, int]:
    errno = pow(2, ptrbits) - errno
    return errno <= MAX_ERRNO, errno


def enrich_error(n: int) -> tuple[str, str]:
    return (errno.errorcode[n], os.strerror(n))


# NOTE: there's probably a better place for this to live than here
def handle_syscall_ret(syscall: str, ret_value: int, ptrbits: int) -> None:
    name = syscall.removeprefix("SYS_")
    is_err, errno = is_error(ret_value, ptrbits)

    if is_err:
        err, desc = enrich_error(errno)
        print(f"{name} syscall failed with {err} ({desc!r})")
    else:
        print(f"{name} syscall returned {ret_value:#x}")
