from __future__ import annotations

import re
from pathlib import Path

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

WEIRD_SYMBOLS_BINARY = get_binary("weird_symbols.native.out")
WEIRD_SYMBOLS_NODEBUG_BINARY = get_binary("weird_symbols_nodebug.native.out")

BINARIES = [
    pytest.param(WEIRD_SYMBOLS_BINARY, id="debug-info"),
    pytest.param(WEIRD_SYMBOLS_NODEBUG_BINARY, id="no-debug-info"),
]

# 'lambda' and {lambda(int)#1} in the name
# can't be escaped with single quotes for lldb
LLDB_UNESCAPABLE_FUNC_SYMBOL: tuple[str, str, str] = (
    "_ZZ11apply_twiceiENKUliE_clEi",
    "apply_twice(int)::{lambda(int)#1}::operator()(int) const",
    "apply_twice(int)::'lambda'(int)::operator()(int) const",
)

# Used in some tests as a representative borked symbol
NICE_FUNC_EXAMPLE: tuple[str, str, None] = (
    "_ZNK5outer5inner3VecssERKS1_",
    "outer::inner::Vec::operator<=>(outer::inner::Vec const&) const",
    None,
)


# (linkage/mangled name, demangled name, LLDB's demangled name if it's different)
FUNC_SYMBOLS: list[tuple[str, str, str | None]] = [
    # anon namespace and () in the name
    ("_ZN12_GLOBAL__N_16hiddenEi", "(anonymous namespace)::hidden(int)", None),
    # & in the name
    (
        "_ZNK5outer5inner3VecplERKS1_",
        "outer::inner::Vec::operator+(outer::inner::Vec const&) const",
        None,
    ),
    # / in the name
    ("_ZNK5outer5inner3VecdvEi", "outer::inner::Vec::operator/(int) const", None),
    # + in the name
    ("_ZN5outer5inner3VecppEv", "outer::inner::Vec::operator++()", None),
    # [] in the name
    ("_ZNK5outer5inner3VecixEi", "outer::inner::Vec::operator[](int) const", None),
    ("_ZNK5outer5inner3VecclEii", "outer::inner::Vec::operator()(int, int) const", None),
    ("_ZN5outer5inner3VecnaEm", "outer::inner::Vec::operator new[](unsigned long)", None),
    # <=> in the name
    NICE_FUNC_EXAMPLE,
    # has return type, unmatched < in the name
    (
        "_ZN5outer5innerltIiEEbRKNS0_3VecET_",
        "bool outer::inner::operator< <int>(outer::inner::Vec const&, int)",
        "bool outer::inner::operator<<int>(outer::inner::Vec const&, int)",
    ),
    # thunk and - in the name
    (
        "_ZThn8_NK5outer5inner6Square2idEv",
        "non-virtual thunk to outer::inner::Square::id() const",
        None,
    ),
    # ... in the name
    ("_Z3sumiz", "sum(int, ...)", None),
    # : in the name
    ("_Z6taggedB2v2v", "tagged[abi:v2]()", None),
    # <> in the name
    ("_Z5firstIiLi3EET_RAT0__S0_", "int first<int, 3>(int (&) [3])", None),
    # * in the name
    ("_Z9call_withPFiiEi", "call_with(int (*)(int), int)", None),
    # "" in the name
    ("_Zli3_kmy", 'operator"" _km(unsigned long long)', None),
    # $ in the name
    ("_ZZ6tripleiENK3$_0clEi", "triple(int)::$_0::operator()(int) const", None),
    # ~ in the name
    ("_ZN7kitchen4TaskD2Ev", "kitchen::Task::~Task()", None),
    # qualifier after signature and . in the name
    (
        "_ZN7kitchen4cookENS_5OrderE.resume",
        "kitchen::cook(kitchen::Order) [clone .resume]",
        "kitchen::cook(kitchen::Order) (.resume)",
    ),
    LLDB_UNESCAPABLE_FUNC_SYMBOL,
]

# nice for testing because it never has debug info, even when compiled with -g
VTABLE: tuple[str, str, None] = (
    "_ZTVN5outer5inner6SquareE",
    "vtable for outer::inner::Square",
    None,
)

# nice example for debug info data symbol resolution
WACKY_STRUCT: tuple[str, str, None] = (
    "_ZN12_GLOBAL__N_111anon_structE",
    "(anonymous namespace)::anon_struct",
    None,
)

# (linkage/mangled name, demangled name, LLDB's demangled name if it's different)
# We touch every type in pwndbg.dbg_mod.TypeCode
DATA_SYMBOLS: list[tuple[str, str, str | None]] = [
    # single word int
    ("global_int", "global_int", None),
    # single word struct
    ("global_struct", "global_struct", None),
    # union
    ("global_union", "global_union", None),
    # enum
    ("global_enum", "global_enum", None),
    # typedef
    ("global_typedef", "global_typedef", None),
    # pointer
    ("global_pointer", "global_pointer", None),
    # bool
    ("global_bool", "global_bool", None),
    # multi word int
    ("_ZN12_GLOBAL__N_18anon_intE", "(anonymous namespace)::anon_int", None),
    # multi word struct
    WACKY_STRUCT,
    # multi word array
    ("_ZN12_GLOBAL__N_15tableE", "(anonymous namespace)::table", None),
    # vtable, never has debug info
    VTABLE,
]

SYMBOLS = FUNC_SYMBOLS + DATA_SYMBOLS


def debugger_name(name: str, lldb_name: str | None) -> str:
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if lldb_name is not None and pwndbg.dbg.name() == DebuggerType.LLDB:
        return lldb_name
    return name


def symbol_address(linkage_name: str) -> int:
    """
    Gets the symbol address without any weird symbol name shenanigens (because
    we are using the linkage name).
    """
    import pwndbg

    addr = pwndbg.dbg.selected_inferior().lookup_symbol(linkage_name)
    assert addr is not None
    return int(addr)


@pytest.mark.parametrize("binary", BINARIES)
@pwndbg_test
async def test_quoted_symbol_argument(ctrl: Controller, binary: Path) -> None:
    """
    We check that every weird symbol concievable can be escaped with single quotes,
    and that we resolve it to the proper address.

    One exception to this is
        "apply_twice(int)::'lambda'(int)::operator()(int) const",
    where LLDB emits single quotes, so a user needs to escape this specially.
    """
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    await launch_to(ctrl, binary, "break_here")

    mismatches = []
    for linkage_name, name, lldb_name in SYMBOLS:
        if (
            pwndbg.dbg.name() == DebuggerType.LLDB
            and linkage_name == LLDB_UNESCAPABLE_FUNC_SYMBOL[0]
        ):
            # Has ' in the name
            continue

        name = debugger_name(name, lldb_name)
        addr = symbol_address(linkage_name)

        # &'name' works for both data and function symbols
        out = await ctrl.execute_and_capture(f"distance &'{name}' {addr:#x}")
        if f"{addr:#x}->{addr:#x} is 0x0 bytes" not in out:
            mismatches.append(f"'{name}': {out.strip()}")

        # But we can use 'name' for function symbols as well
        if (linkage_name, name, lldb_name) in FUNC_SYMBOLS:
            out = await ctrl.execute_and_capture(f"distance '{name}' {addr:#x}")
            if f"{addr:#x}->{addr:#x} is 0x0 bytes" not in out:
                mismatches.append(f"'{name}': {out.strip()}")

    assert mismatches == []


@pytest.mark.parametrize("binary", BINARIES)
@pwndbg_test
async def test_lldb_lambda_symbol_argument(ctrl: Controller, binary: Path) -> None:
    """
    We test the LLDB weirdness here.
    """
    # TODO
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.LLDB:
        pytest.skip("Only LLDB puts single quotes in demangled lambda names")

    await launch_to(ctrl, binary, "break_here")

    name = "apply_twice(int)::'lambda'(int)::operator()(int) const"
    addr = symbol_address("_ZZ11apply_twiceiENKUliE_clEi")

    out = await ctrl.execute_and_capture(f'distance "{name}" {addr:#x}')
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out


@pytest.mark.parametrize("binary", BINARIES)
@pwndbg_test
async def test_command_argument_parsing(ctrl: Controller, binary: Path) -> None:
    """
    Check that command argument parsing works, using funky function names.

    Stuff that differs for debug info binaries and no-debug-info binaries is
    in a seperate test.
    """
    await launch_to(ctrl, binary, "break_here")

    # = Lexing tests that don't involve a weird symbol

    # Sanity check
    out = await ctrl.execute_and_capture("distance 1 1")
    assert "0x1->0x1 is 0x0 bytes (0x0 words)" in out

    # Single quotes can mean a single character
    out = await ctrl.execute_and_capture("distance '1' 1")
    assert "0x31->0x1 is -0x30 bytes (-0x6 words)" in out

    # Even hex escapes are supported
    out = await ctrl.execute_and_capture("distance '\\x41' 1")
    assert "0x41->0x1 is -0x40 bytes (-0x8 words)" in out

    # But if it's more characters, it tries a symbol lookup
    out = await ctrl.execute_and_capture("distance '123' 1")
    assert 'No symbol "123" in current context' in out

    # Expression eval also doesn't work, as expected
    out = await ctrl.execute_and_capture("distance '1+1' 1")
    assert 'No symbol "1+1" in current context' in out

    # Double quotes works
    out = await ctrl.execute_and_capture('distance "1" 1')
    assert "0x1->0x1 is 0x0 bytes (0x0 words)" in out

    # Multi-character double quotes are not symbols!
    out = await ctrl.execute_and_capture('distance "123" 1')
    assert "0x7b->0x1 is -0x7a bytes (-0x10 words)" in out

    # We can have expressions with whitespace in double quotes
    out = await ctrl.execute_and_capture('distance "1 + 1" 1')
    assert "0x2->0x1 is -0x1 bytes (-0x1 words)" in out

    # And combine them with expressions without double quotes
    out = await ctrl.execute_and_capture('distance 1+"1 + 1"+1 1')
    assert "0x4->0x1 is -0x3 bytes (-0x1 words)" in out

    # Multiple double quotes combine into one token
    out = await ctrl.execute_and_capture('distance "1 ""+ 1" 1')
    assert "0x2->0x1 is -0x1 bytes (-0x1 words)" in out

    # Can't combine "" and '' though
    out = await ctrl.execute_and_capture("""distance "1 "'+ 1' 1""")
    assert "syntax error" in out

    # Unmatched double quote
    out = await ctrl.execute_and_capture("""distance "1+1 1""")
    assert "syntax error" in out

    # Unmatched single quote
    out = await ctrl.execute_and_capture("""distance '1+1 1""")
    assert "Unmatched single quote" in out

    # = Lexing with a wacky function symbol

    linkage_name, name, lldb_name = NICE_FUNC_EXAMPLE
    name = debugger_name(name, lldb_name)
    addr = symbol_address(linkage_name)

    # Linkage name always works without quotes
    out = await ctrl.execute_and_capture(f"distance {linkage_name} {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # Properly quoted symbol
    # Value of function symbol in gdb is the address of the function
    out = await ctrl.execute_and_capture(f"distance '{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # Plain name doesn't work
    # Because we get multiple tokens due to whitespace
    out = await ctrl.execute_and_capture(f"distance {name} {addr:#x}")
    assert "debugger couldn't resolve argument" in out

    # Double quotes don't work
    # Since they get stripped when passed to the underlying debugger's
    # expression evaluator.
    out = await ctrl.execute_and_capture(f'distance "{name}" {addr:#x}')
    assert "debugger couldn't resolve argument" in out

    # Single quotes in double quotes works
    # Because the double quotes get stripped.
    out = await ctrl.execute_and_capture(f"""distance "'{name}'" {addr:#x}""")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # Multiple double quotes is also fine!
    # (if there is a single quote inside)
    out = await ctrl.execute_and_capture(f"""distance ""'{name}'"" {addr:#x}""")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # We can use & on a function symbol
    out = await ctrl.execute_and_capture(f"distance &'{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # We can add offsets
    out = await ctrl.execute_and_capture(f"distance &'{name}'+123 {addr + 123:#x}")
    assert f"{addr + 123:#x}->{addr + 123:#x} is 0x0 bytes" in out

    # And add double quotes to make such addition allowed to have spaces
    out = await ctrl.execute_and_capture(f"""distance "'{name}' + 123" {addr + 123:#x}""")
    assert f"{addr + 123:#x}->{addr + 123:#x} is 0x0 bytes" in out

    # Or even add multiple symbols together
    out = await ctrl.execute_and_capture(f"distance (long)'{name}'+(long)'{name}' {2 * addr:#x}")
    assert f"{2 * addr:#x}->{2 * addr:#x} is 0x0 bytes" in out

    # Wrapped in double quotes with spaces and an offset at the end
    out = await ctrl.execute_and_capture(
        f"""distance "(long)'{name}' + (long)'{name}'"+123 {2 * addr + 123:#x}"""
    )
    assert f"{2 * addr + 123:#x}->{2 * addr + 123:#x} is 0x0 bytes" in out

    # = Lexing with a wacky data symbol

    # There is no type for this variable even in a binary with debug info
    linkage_name, name, lldb_name = VTABLE
    name = debugger_name(name, lldb_name)
    addr = symbol_address(linkage_name)

    # Linkage name always works without quotes
    out = await ctrl.execute_and_capture(f"distance &{linkage_name} {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # We can't just use it in an expression since we have no type
    out = await ctrl.execute_and_capture(f"distance '{name}' {addr:#x}")
    assert "no debug info (type info)" in out

    # But we can take its address
    out = await ctrl.execute_and_capture(f"distance &'{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # And yeah we can do all the other wacky stuff we can do with
    # functions as well.
    out = await ctrl.execute_and_capture(
        f"""distance "(long)&'{name}' + (long)&'{name}'"+123 {2 * addr + 123:#x}"""
    )
    assert f"{2 * addr + 123:#x}->{2 * addr + 123:#x} is 0x0 bytes" in out

    # = PLT symbols

    name = "getpid@plt"  # function

    # By default they don't work because @ is a special character
    out = await ctrl.execute_and_capture(f"distance {name} {name}")
    assert "debugger couldn't resolve argument" in out

    # But with quotes they do!
    out = await ctrl.execute_and_capture(f"distance '{name}' '{name}'")
    assert "is 0x0 bytes (0x0 words)" in out

    name = "getpid@got.plt"  # variable

    # Same story for the varaible
    out = await ctrl.execute_and_capture(f"distance {name} {name}")
    assert "debugger couldn't resolve argument" in out

    # It works with quotes
    out = await ctrl.execute_and_capture(f"distance '{name}' '{name}'")
    assert "is 0x0 bytes (0x0 words)" in out


@pwndbg_test
async def test_command_argument_parsing_w_dinfo(ctrl: Controller) -> None:
    """
    Same as test_command_argument_parsing() but tests stuff that requires debug info.
    """
    await launch_to(ctrl, WEIRD_SYMBOLS_BINARY, "break_here")

    # = Calling a function

    _, name, lldb_name = NICE_FUNC_EXAMPLE
    name = debugger_name(name, lldb_name)

    # No need to cast the function type
    # The return value of the function will be `std::__1::strong_ordering` so we extract the value
    # with .__value_ .
    out = await ctrl.execute_and_capture(f"distance '{name}'(&gparam1,gparam2).__value_ -1")
    assert "0xffffffffffffffff->0xffffffffffffffff is 0x0 bytes (0x0 words)" in out

    # Note that we can't have spaces in the parameter list
    out = await ctrl.execute_and_capture(f"distance '{name}'(&gparam1, gparam2).__value_ -1")
    assert "syntax error" in out

    # Unless we wrap it in double quotes
    out = await ctrl.execute_and_capture(f"""distance "'{name}'(&gparam1, gparam2).__value_" -1""")
    assert "0xffffffffffffffff->0xffffffffffffffff is 0x0 bytes (0x0 words)" in out

    # = Data symbol expressions

    linkage_name, name, lldb_name = WACKY_STRUCT
    name = debugger_name(name, lldb_name)
    addr = symbol_address(linkage_name)

    # Sanity check
    # Note that '' are required even in the gdb print
    out = await ctrl.execute_and_capture(f"p '{name}'")
    assert (
        """ = {
  x = 0x5555,
  y = 0x6666
}"""
        in out
    )

    # NOTE: Okay so, the VALUE of this variable is a struct.
    # However, the struct cannot be coerced to an int.
    # Pwndbg will then use the ADDRESS of the struct instead (see parse_command_argument_to_int()).
    # This might be unintuitive behaviour, we will need to see if users complain.
    # (because if you don't have debug info, we require that you put &'', because there
    # is no way for us to know whether coercing the value to an int would work or not without type info)
    out = await ctrl.execute_and_capture(f"dist '{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # We can still use the & syntax
    out = await ctrl.execute_and_capture(f"dist &'{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # And even access the fields of the struct
    out = await ctrl.execute_and_capture(f"dist '{name}'.x 0x5555")
    assert "0x5555->0x5555 is 0x0 bytes" in out

    # But watch where you put the quotes
    out = await ctrl.execute_and_capture(f"dist '{name}.x' 0x5555")
    assert "debugger couldn't resolve argument" in out

    # And arithmetic works as we already know
    out = await ctrl.execute_and_capture(f"""dist "'{name}'.x + 1" 0x5556""")
    assert "0x5556->0x5556 is 0x0 bytes" in out

    # Though trying to add to the symbol itself will not work,
    # because the symbol has a struct value.
    out = await ctrl.execute_and_capture(f"""dist "'{name}' + 1" 0x5555""")
    assert 'No symbol "operator+" in current context.' in out


@pwndbg_test
async def test_command_argument_parsing_stripped(ctrl: Controller) -> None:
    """
    Same as test_command_argument_parsing() but tests stuff that requires no debug info.
    """
    await launch_to(ctrl, WEIRD_SYMBOLS_NODEBUG_BINARY, "break_here")

    # = Calling a function

    _, name, lldb_name = NICE_FUNC_EXAMPLE
    name = debugger_name(name, lldb_name)

    # Without debug info it's annoying because we have to cast the type
    out = await ctrl.execute_and_capture(f"distance '{name}'(&gparam1,gparam2).__value_ -1")
    assert "no debug info (type info) available for" in out

    # Since the type has spaces, we have to use double quotes
    # And put the cast in () as well
    # And since gparam2 doesn't have a type, we will use it's address (we could also cast it).
    # We don't need to .__value_ because we cast the return type.
    functype = "(signed char (*)(void *, void *))"
    out = await ctrl.execute_and_capture(
        f"""distance "({functype}'{name}')(&gparam1, &gparam2)" -1"""
    )
    assert "0xffffffffffffffff->0xffffffffffffffff is 0x0 bytes (0x0 words)" in out

    # = Data symbol expressions

    linkage_name, name, lldb_name = WACKY_STRUCT
    name = debugger_name(name, lldb_name)
    addr = symbol_address(linkage_name)

    # This won't work, because we don't know what the type is
    # NOTE: We could easily make this work by adding a fallback lookup_symbol()
    # to parse_command_argument(), but this would result in integer variables
    # getting their addresses returned when no debug info is available, and getting
    # their values returned when debug info is available.
    # To be consistent, we just fail.
    out = await ctrl.execute_and_capture(f"dist '{name}' {addr:#x}")
    assert "no debug info (type info) available for" in out

    # We can take the address though
    out = await ctrl.execute_and_capture(f"dist &'{name}' {addr:#x}")
    assert f"{addr:#x}->{addr:#x} is 0x0 bytes" in out

    # And can cast it to a value
    out = await ctrl.execute_and_capture(f"dist (long)'{name}' 0x5555")
    assert "0x5555->0x5555 is 0x0 bytes" in out

    # We can be a bit cheeky to pull out y
    out = await ctrl.execute_and_capture(f"dist ((long*)&'{name}')[1] 0x6666")
    assert "0x6666->0x6666 is 0x0 bytes" in out


@pytest.mark.parametrize("binary", BINARIES)
@pwndbg_test
async def test_symbol_name_at_address(ctrl: Controller, binary: Path) -> None:
    """
    Tests that symbol_name_at_address() can recover a demangled symbol name given its address.

    See issue #1600 .
    """
    import pwndbg

    await launch_to(ctrl, binary, "break_here")
    inf = pwndbg.dbg.selected_inferior()

    for linkage_name, name, lldb_name in FUNC_SYMBOLS:
        name = debugger_name(name, lldb_name)
        addr = symbol_address(linkage_name)

        assert inf.symbol_name_at_address(addr) == name


@pwndbg_test
async def test_context_backtrace_show_proper_symbol_names(ctrl: Controller) -> None:
    """
    Test that the backtrace renders the demangled symbols properly.

    See issue #752 .
    """
    await ctrl.launch(WEIRD_SYMBOLS_BINARY)

    # The first call to bump() is from the coroutine
    await ctrl.execute("b bump")
    await ctrl.cont()

    backtrace = (await ctrl.execute_and_capture("context backtrace")).split("\n")

    # Example backtrace:
    #
    # LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
    # ─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
    #  ► 0 0x100d3b7      bump(int)+7
    #    1 0x100de53      kitchen::cook(kitchen::Order) [clone .resume]+307
    #    2 0x100e878      std::__1::coroutine_handle<kitchen::Task::promise_type>::res
    #                     ume[abi:ne200100]() const+24
    #    3 0x100da7a      main+362
    #    4 0x7ffff7c27781 __libc_start_call_main+129
    #    5 0x7ffff7c278b9 __libc_start_main+137
    #    6 0x100d215      _start+37
    # ────────────────────────────────────────────────────────────────────────────────

    assert "LEGEND" in backtrace[0]
    assert "BACKTRACE" in backtrace[1]

    # Match bump(int)+7 or similar offset
    assert re.match(r".*0\s+0x[0-9a-f]+\s+bump\(int\)\+\d+$", backtrace[2])

    # Match kitchen::cook(kitchen::Order) [clone .resume]+307 or similar offset
    assert re.match(
        r".*1\s+0x[0-9a-f]+\s+kitchen::cook\(kitchen::Order\) \[clone \.resume\]\+\d+$",
        backtrace[3],
    )

    # libc++ resumes the coroutine, and its name wraps onto a second line
    assert re.match(
        r".*2\s+0x[0-9a-f]+\s+std::__1::coroutine_handle<kitchen::Task::promise_type>::res$",
        backtrace[4],
    )
    assert re.match(r"\s+ume\[abi:\w+\]\(\) const\+\d+$", backtrace[5])

    # Match main+87 or similar offset
    assert re.match(r".*3\s+0x[0-9a-f]+\s+main\+\d+$", backtrace[6])

    # The rest of the backtrace depends on glibc (__libc_start_call_main, __libc_start_main)

    assert "──────" in backtrace[-2]
    assert backtrace[-1] == ""
