from __future__ import annotations

import gdb

import pwndbg.color.message
import tests

BINARY = tests.binaries.get("reference-binary.out")


def prepare_prompt(is_proc_alive):
    prompt = "pwndbg> "

    prompt = "\x02" + prompt + "\x01"  # STX + prompt + SOH
    if is_proc_alive:
        prompt = pwndbg.color.message.alive_prompt(prompt)
    else:
        prompt = pwndbg.color.message.prompt(prompt)
    prompt = "\x01" + prompt + "\x02"  # SOH + prompt + STX

    return prompt


# check if expected and actual prompts correspond
def run_prompt_check(is_proc_alive):
    expected = prepare_prompt(is_proc_alive=is_proc_alive)
    result = gdb.execute("show prompt", to_string=True)
    result = result.replace("\\001", "\x01")
    result = result.replace("\\002", "\x02")
    result = result.replace(r"\e", "\x1b")
    result = result.split('"')[1].encode("latin1")
    expected = expected.encode("latin1")
    print(f"Expected ---> {expected}")
    print(f"Result   ---> {result}")

    assert result == expected


def test_prompt_recolor(start_binary):
    gdb.execute("set disable-colors off")

    # Check normal prompt
    run_prompt_check(is_proc_alive=False)

    # Check prompt when process is alive
    start_binary(BINARY)
    gdb.prompt_hook(*[])  # run prompt hook to update prompt
    run_prompt_check(is_proc_alive=True)

    gdb.execute("continue")
    # Check prompt after process died
    gdb.prompt_hook(*[])  # run prompt hook to update prompt
    run_prompt_check(is_proc_alive=False)

    gdb.execute("set disable-colors off")
