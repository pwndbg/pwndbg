"""
Objective-C Parsing Commands

Commands in this module expose functionality present in `pwndbg.aglib.objc`
directly to users instead of indirectly through other mechanisms like target
resolution in the context.
"""

from __future__ import annotations

import argparse
from collections.abc import Generator

import pwndbg
import pwndbg.aglib.macho
import pwndbg.aglib.objc
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Objective-C Support

This command is composed of a number of subcommands providing support for
inspecting and interacting with the Objective-C ABI in Darwin-based systems.
""",
)
subparsers = parser.add_subparsers(dest="command", required=True)

subparser = subparsers.add_parser(
    name="show-class",
    help="Show information about a given Objective-C class",
    description="""Show information about a given Objective-C class

The information is presented in a pseudo-Objective-C syntax, that displays
the value string for properties and the addresses of IMP pointers and selectors
for methods, but omits type information.

It is given in the form:
```
@implementation <ClassName> : <SuperName>

@property <PropertyName> = <PropertyValue>

- <ClassMethodSelector> (<SelectorAddress>) @ <IMP>

+ <InstanceMethodSelector> (<SelectorAddress>) @ <IMP>

@end
```
""",
)

subparser.add_argument(
    "-m",
    "--module",
    type=str,
    help="Name of the module from which the class is going to be looked up. By default this is the main module.",
)

mut_ex_grp = subparser.add_mutually_exclusive_group(required=True)
mut_ex_grp.add_argument(
    "-a", "--address", type=int, help="Address at which the class metadata starts"
)
mut_ex_grp.add_argument("-n", "--name", type=str, help="Name of the class to display")


subparser = subparsers.add_parser(
    name="list-classes",
    help="Lists Objective-C classes present in the process",
    description="Lists Objective-C classes present in the process",
)
subparser.add_argument(
    "-f",
    "--full",
    action="store_true",
    help="Display full information for each class in the manner of objc-show-class, rather than just their names.",
)

mut_ex_grp = subparser.add_mutually_exclusive_group()
mut_ex_grp.add_argument(
    "-A",
    "--all-with-shared-cache",
    action="store_true",
    help="List classes from all modules in the process, including those in the shared cache.",
)
mut_ex_grp.add_argument(
    "-m",
    "--module",
    type=str,
    help="Name of the module from which the classes are going to be listed. By default this is the main module.",
)
mut_ex_grp.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="List classes from all modules in the process, except those in the shared cache.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.DARWIN,
)
@pwndbg.commands.OnlyWhenRunning
def objc(
    command: str,
    module: str | None = None,
    name: str | None = None,
    address: int | None = None,
    all: bool | None = None,
    all_with_shared_cache: bool | None = None,
    full: bool | None = None,
) -> None:
    match command:
        case "show-class":
            _objc_show_class(module=module, name=name, address=address)
        case "list-classes":
            _objc_list_classes(
                module=module, all=all, all_with_shared_cache=all_with_shared_cache, full=full
            )


def _objc_show_class(module: str | None, name: str | None, address: int | None) -> None:
    klass: pwndbg.aglib.objc.Class | None = None
    lookup_descr: str | None

    if name is not None:
        # This is a name-based lookup.
        if module is None:
            module = pwndbg.dbg.selected_inferior().main_module_name()
            if module is None:
                print(
                    message.error("error:"),
                    "no main module could be found, please specify a module explicitly with --module",
                )
                return

        lookup_descr = f"named {name!r} in module {module!r}"

        for candidate_module, _, classes in pwndbg.aglib.objc.classes_per_module():
            if candidate_module != module:
                continue

            for candidate in classes:
                if candidate.name == name.encode():
                    klass = candidate
                    break
    elif address is not None:
        # This is an address-based lookup.
        lookup_descr = f"at address {address:#x}"

        klass = pwndbg.aglib.objc.Class(address)
    else:
        raise AssertionError("Either address or name lookup must be selected by this point.")

    if klass is None:
        print(message.error("error:"), "no class could be found", lookup_descr)
        return

    _print_class_lossy(klass)


def _objc_list_classes(
    all: bool | None, all_with_shared_cache: bool | None, module: str | None, full: bool | None
) -> None:
    if all:
        _do_list_classes(None, pwndbg.aglib.macho.shared_cache(), full is not None and full)
    elif all_with_shared_cache:
        _do_list_classes(None, None, full is not None and full)
    else:
        if module is None:
            # No module has been explicitly selected, pick the main one.
            module = pwndbg.dbg.selected_inferior().main_module_name()
            if module is None:
                print(
                    message.error("error:"),
                    "no main module could be found, please specify a module explicitly with --module",
                )
                return

        _do_list_classes(module, None, full is not None and full)


def _print_class_lossy(klass: pwndbg.aglib.objc.Class) -> None:
    # Read the names of the class itself and its superclass.
    name: str = "<UNKNOWN>"
    try:
        name = klass.name.decode()
    except Exception as e:
        print(message.warn("warning:"), "could not read class name:", e)

    superclass_name: str | None = "<UNKNOWN>"
    try:
        metaclass = klass.superclass
        if metaclass is None:
            superclass_name = None
        else:
            superclass_name = metaclass.name.decode()
    except Exception as e:
        print(message.warn("warning:"), "could not read superclass name:", e)

    print(f"@interface {name}", end="")
    if superclass_name is not None:
        print(f" : {superclass_name}", end="")
    print()

    # Read class properties.
    try:
        _print_class_properties_lossy(klass.properties)
    except Exception as e:
        print(message.warn("warning:"), "could not read class properties:", e)

    # Read class methods in the metaclass. These are actually the class methods
    # of the actual class, with the class methods in the class itself being its
    # instance methods.
    try:
        metaclass = klass.cls
        if metaclass is not None:
            # Only consider non-metaclass classes.
            _print_method_lossy(False, metaclass.methods)
    except Exception as e:
        print(message.warn("warning:"), "could not read class methods:", e)

    # Read instance methods.
    try:
        _print_method_lossy(True, klass.methods)
    except Exception as e:
        print(message.warn("warning:"), "could not read instance methods:", e)

    print()
    print("@end")


def _print_class_properties_lossy(
    properties: Generator[pwndbg.aglib.objc.ClassProperty, None, None],
) -> None:
    first = True
    for i, prop in enumerate(properties):
        if first:
            first = False
            print()

        prop_name: str = "<UNKNOWN>"
        try:
            prop_name = prop.name.decode()
        except Exception as e:
            print(message.warn("warning:"), f"could not read class property name at index {i}:", e)

        value: bytes = b"<UNKNOWN>"
        try:
            value = prop.value
        except Exception as e:
            print(
                message.warn("warning:"),
                f"could not read class property value at index {i}:",
                e,
            )

        print(f"@property {prop_name} = {value!r}")


def _print_method_lossy(
    instance: bool, methods: Generator[pwndbg.aglib.objc.Method, None, None]
) -> None:
    prefix = "-" if instance else "+"
    kind = "instance" if instance else "class"

    first = True
    for i, method in enumerate(methods):
        if first:
            first = False
            print()
        sel_addr: str = "<UNKNOWN>"
        try:
            sel_addr = f"{method.sel.address:#x}"
        except Exception as e:
            print(
                message.warn("warning:"),
                f"could not read {kind} method selector address index {i}:",
                e,
            )

        sel_name: str = "<UNKNOWN>"
        try:
            sel_name = method.sel.name.decode()
        except Exception as e:
            print(
                message.warn("warning:"),
                f"could not read {kind} method selector address index {i}:",
                e,
            )

        imp: str = "<UNKNOWN>"
        try:
            imp = f"{method.imp:#x}"
        except Exception as e:
            print(message.warn("warning:"), f"could not read {kind} method IMP at index {i}:", e)

        print(f"{prefix} {sel_name} ({sel_addr}) @ {imp}")


def _do_list_classes(
    module: str | None,
    except_from_shared_cache: pwndbg.aglib.macho.DyldSharedCache | None,
    full: bool,
) -> None:
    shared_cache_skipped = 0
    for candidate_module, section_address, classes in pwndbg.aglib.objc.classes_per_module():
        if except_from_shared_cache and except_from_shared_cache.is_address_in_shared_cache(
            section_address
        ):
            # Skip modules from the shared cache if we were requested to do so.
            shared_cache_skipped += 1
            continue
        if module and candidate_module != module:
            # Skip modules that don't match the target module if we were given one.
            continue

        first = True
        for i, klass in enumerate(classes):
            if first:
                print(f"Classes from module '{candidate_module}':")
                first = False

            if full:
                _print_class_lossy(klass)
                print()
            else:
                try:
                    print(f"    {klass.name.decode()}")
                except Exception as e:
                    print(
                        "    ",
                        message.warn("warning:"),
                        f"could not read the name of the class at index {i}:",
                        e,
                    )

    if shared_cache_skipped > 0:
        print(
            message.info("info:"),
            f"omitted {shared_cache_skipped} modules from the DYLD Shared Cache, use -A to expand",
        )
