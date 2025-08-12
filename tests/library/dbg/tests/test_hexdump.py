from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

BINARY = get_binary("reference-binary.out")


async def run_tests(ctrl: Controller, stack: int, use_big_endian: bool, expected: str) -> None:
    from pwnlib.util.cyclic import cyclic

    import pwndbg
    import pwndbg.aglib.memory

    pwndbg.config.hexdump_group_use_big_endian.value = use_big_endian

    # Put some data onto the stack
    pwndbg.aglib.memory.write(stack, cyclic(0x100))

    # Test empty hexdump
    result = await ctrl.execute_and_capture("hexdump 0")
    assert result == "Could not read memory at specified address\n"

    results = []
    # TODO: Repetition is not working in tests
    results.append(await ctrl.execute_and_capture(f"hexdump {stack} 64"))
    results.append(await ctrl.execute_and_capture(f"hexdump {stack} 3"))

    assert len(results) == len(expected)
    for i, result in enumerate(results):
        expected_result = expected[i]
        assert result == expected_result


@pwndbg_test
async def test_hexdump(ctrl: Controller) -> None:
    import pwndbg
    import pwndbg.aglib.regs

    await ctrl.launch(BINARY)
    pwndbg.config.hexdump_group_width.value = -1

    pwndbg.config.hexdump_byte_separator.value = ""
    stack_addr = pwndbg.aglib.regs.rsp - 0x100

    expected = [
        f"""+0000 0x{stack_addr:x}  6161616261616161 6161616461616163 │aaaabaaa│caaadaaa│
+0010 0x{stack_addr+0x10:x}  6161616661616165 6161616861616167 │eaaafaaa│gaaahaaa│
+0020 0x{stack_addr+0x20:x}  6161616a61616169 6161616c6161616b │iaaajaaa│kaaalaaa│
+0030 0x{stack_addr+0x30:x}  6161616e6161616d 616161706161616f │maaanaaa│oaaapaaa│\n""",
        f"""+0000 0x{stack_addr:x}            616161                  │aaa     │        │\n""",
    ]
    await run_tests(ctrl, stack_addr, True, expected)

    expected = [
        f"""+0000 0x{stack_addr:x}  6161616162616161 6361616164616161 │aaaabaaa│caaadaaa│
+0010 0x{stack_addr+0x10:x}  6561616166616161 6761616168616161 │eaaafaaa│gaaahaaa│
+0020 0x{stack_addr+0x20:x}  696161616a616161 6b6161616c616161 │iaaajaaa│kaaalaaa│
+0030 0x{stack_addr+0x30:x}  6d6161616e616161 6f61616170616161 │maaanaaa│oaaapaaa│\n""",
        f"""+0000 0x{stack_addr:x}  616161                            │aaa     │        │\n""",
    ]
    await run_tests(ctrl, stack_addr, False, expected)


@pwndbg_test
async def test_hexdump_collapse_lines(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await ctrl.launch(BINARY)
    sp = pwndbg.aglib.regs.rsp

    pwndbg.aglib.memory.write(sp, b"abcdefgh\x01\x02\x03\x04\x05\x06\x07\x08" * 16)

    async def hexdump_lines(lines: int):
        offset = (lines - 1) * 0x10  # last line offset
        skipped_lines = lines - 2

        out = await ctrl.execute_and_capture(f"hexdump $rsp {offset+16}")

        expected = (
            f"+0000 0x{sp:x}  61 62 63 64 65 66 67 68  01 02 03 04 05 06 07 08  │abcdefgh│........│\n"
            f"... ↓            skipped {skipped_lines} identical lines ({skipped_lines*16} bytes)\n"
            f"+{offset:04x} 0x{sp+offset:x}  61 62 63 64 65 66 67 68  01 02 03 04 05 06 07 08  │abcdefgh│........│\n"
        )
        assert out == expected

    await hexdump_lines(3)
    await hexdump_lines(4)
    await hexdump_lines(10)


@pwndbg_test
async def test_hexdump_saved_address_and_offset(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs
    import pwndbg.commands.hexdump

    # TODO There is no way to verify repetition: the last_address and offset are reset
    # before each command
    await ctrl.launch(BINARY)
    sp = pwndbg.aglib.regs.rsp

    SIZE = 21

    pwndbg.aglib.memory.write(sp, b"abcdefgh\x01\x02\x03\x04\x05\x06\x07\x08" * 16)

    out1 = await ctrl.execute_and_capture(f"hexdump $rsp {SIZE}")
    out2 = (
        f"+0000 0x{sp:x}  61 62 63 64 65 66 67 68  01 02 03 04 05 06 07 08  │abcdefgh│........│\n"
        f"+0010 0x{sp+0x10:x}  61 62 63 64 65                                    │abcde   │        │\n"
    )

    assert out1 == out2
    assert pwndbg.commands.hexdump.hexdump.last_address == sp + SIZE
    assert pwndbg.commands.hexdump.hexdump.offset == SIZE


@pwndbg_test
async def test_hexdump_limit_check(ctrl: Controller):
    """
    Tests that the hexdump command respects the hexdump-limit-mb settings.
    """
    import pwndbg.aglib.regs
    from pwndbg.dbg import Error

    await ctrl.launch(BINARY)
    sp = pwndbg.aglib.regs.rsp

    # Default limit is 10 MB
    default_limit_mb = 10
    limit_bytes = default_limit_mb * 1024 * 1024
    count_over_limit = limit_bytes + 1
    count_within_limit = limit_bytes // 2  # Using a value clearly within the limit

    # 1. Test that count over the default limit raises PwndbgError
    print(f"Testing count over default limit ({count_over_limit} bytes)")
    with pytest.raises(Error, match="exceeds the current limit"):
        await ctrl.execute(f"hexdump {sp} {count_over_limit}")
    print(" -> Correctly raised error.")

    # 2. Test that count within the default limit works
    print(f"Testing count within default limit ({count_within_limit} bytes)")
    # We don't expect an error here. Just executing it is the test.
    # We could assert on the output, but simply not crashing/erroring is the main goal.
    try:
        await ctrl.execute(f"hexdump {sp} {count_within_limit}")
    except Exception as e:
        pytest.fail(f"Hexdump failed unexpectedly with count within limit: {e}")
    print(" -> Correctly executed.")

    # 3. Test increasing the limit allows larger dumps
    new_limit_mb = 15
    count_over_default_under_new = (default_limit_mb + 1) * 1024 * 1024
    print(f"Setting limit to {new_limit_mb} MB and testing count {count_over_default_under_new}")
    await ctrl.execute(f"set hexdump-limit-mb {new_limit_mb}")
    try:
        await ctrl.execute(f"hexdump {sp} {count_over_default_under_new}")
    except Exception as e:
        pytest.fail(f"Hexdump failed unexpectedly after increasing limit: {e}")
    print(" -> Correctly executed after increasing limit.")

    # 4. Test disabling the limit (set to 0) allows larger dumps
    print(f"Setting limit to 0 and testing count {count_over_default_under_new}")
    await ctrl.execute("set hexdump-limit-mb 0")
    try:
        await ctrl.execute(f"hexdump {sp} {count_over_default_under_new}")
    except Exception as e:
        pytest.fail(f"Hexdump failed unexpectedly after disabling limit: {e}")
    print(" -> Correctly executed after disabling limit.")
