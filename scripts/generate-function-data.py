#!/usr/bin/env python3

from __future__ import annotations

import re

import requests

URL = "https://syscalls.mebeim.net/db/x86/64/x64/latest/table.json"

_IDENT_RE = re.compile(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$")


def parse_arg(arg: str) -> tuple[str, int, str]:
    """
    Returns [type name, deref count, name].
    """
    arg = arg.strip()

    m = _IDENT_RE.search(arg)
    assert m

    name = m.group(1)
    assert isinstance(name, str)

    type_part = arg[: m.start()].strip()
    deref = type_part.count("*")

    type_str = type_part.replace("*", " ")
    type_str = " ".join(type_str.split())

    return (type_str, deref, name)


def main() -> None:
    syscall_table = requests.get(URL).json()

    syscalls = syscall_table["syscalls"]

    for entry in syscalls:
        if "name" in entry:
            name = entry["name"]
        elif "origname" in entry:
            name = entry["origname"]
        else:
            # Something is fucked up
            name = "unknown"

        fname = f"SYS_{name.strip()}"

        sig = entry.get("signature")
        arg_strs = [str(x) for x in sig]

        args = []
        for i, a in enumerate(arg_strs):
            t, d, n = parse_arg(a)
            if n == "arg0" and a.strip() != "void":
                n = f"arg{i}"
            args.append((t, d, n))

        print(f'"{fname}": Function(')
        print('     type="long",')  # syscalls all technically return long
        print("     derefcnt=0,")
        print(f'    name="{fname}",')
        if not args:
            print("  args=[],")
        else:
            print("     args=[")
            for t, d, n in args:
                print(f'        Argument(type="{t}", derefcnt={d}, name="{n}"),')
            print("     ],")
        print("),")


if __name__ == "__main__":
    main()
