"""
This command sends information on the current debugging context to OpenAI's
GPT-3 large language model and asks it a question supplied by the user. It then
displays GPT-3's response to that question to the user.
"""

__AUTHOR__ = "Olivia Lucca Fraser"
__VERSION__ = 0.1
__LICENSE__ = "MIT"

import argparse
import os
import re

import gdb
import openai

import pwndbg
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.commands import context
from pwndbg.gdblib import regs as REGS

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

LAST_QUESTION = []
LAST_ANSWER = []
HISTORY_LENGTH = 3
LAST_PC = None
STACK_DEPTH = 16
LAST_COMMAND = None


def build_prompt(question, command=None):
    if command is not None:
        return build_prompt_from_command(question, command)

    decompile = False
    ## First, get the current GDB context
    ## Let's begin with the assembly near the current instruction
    try:
        # asm = gdb.execute("capstone-disassemble --length 32 $pc", to_string=True)
        asm_rows = pwndbg.gdblib.nearpc.nearpc(emulate=True, lines=16)
        asm = "\n".join(asm_rows)
    except Exception as e:
        print(f"Error: {e}")
        asm = gdb.execute("x/16i $pc", to_string=True)
    ## Next, let's get the registers
    # regs = gdb.execute("info registers", to_string=True)
    regs_rows = context.get_regs()
    regs = "\n".join(regs_rows)
    flags = None
    try:
        flags = gdb.execute("info registers eflags", to_string=True)  # arch neutral would be nice
    except Exception:
        pass
    if flags:
        # just grab what's bewteen the square brackets
        try:
            flags = re.search(r"\[(.*)\]", flags).group(1)
        except Exception:
            pass
    ## Finally, let's get the stack
    # stack = gdb.execute("x/16x $sp", to_string=True)
    stack_rows = pwndbg.commands.telescope.telescope(REGS.sp, to_string=True, count=16)
    stack = "\n".join(stack_rows)
    ## and the backtrace
    trace = gdb.execute("bt", to_string=True)
    ## the function arguments, if available
    args = gdb.execute("info args", to_string=True)
    ## and the local variables, if available
    local_vars = None  # gdb.execute("info locals", to_string=True)
    ## and source information, if available
    source = gdb.execute("list", to_string=True)
    if len(source.split("\n")) < 3:
        try:
            source = pwndbg.ghidra.decompile()
            decompile = True
        except Exception as e:
            pass
    ## Now, let's build the prompt
    prompt = "Consider the following context in the GDB debugger:\n"

    if True or asm:
        prompt += f"""These are the next assembly instructions to be executed:

```
{asm}
```

"""
    if True or regs:
        prompt += f"""Here are the registers, '*' indicates a recent change:

```
{regs}
```

"""
    if flags:
        prompt += f"""The flags {flags} are set.\n\n"""
    if True or stack:
        prompt += f"""Here is the stack:

```
{stack}
```

"""
    if True or trace:
        prompt += f"""Here is the backtrace:

```
{trace}
```
"""
    if args and "No symbol table info available" not in args:
        prompt += f"""Here are the function arguments:

```
{args}
```
"""

    if local_vars and "No symbol table info available" not in local_vars:
        prompt += f"""Here are the local variables:

```
{local_vars}
```
"""

    if source:
        prompt += f"""Here is the {'decompiled ' if decompile else ''}source code near the current instruction:

```
{source}
```
"""
    return finish_prompt(prompt, question)


def build_prompt_from_command(question, command):
    prompt = f"""Running the command `{command}` in the GDB debugger yields the following output:\n"""
    output = gdb.execute(command, to_string=True)
    print(output)
    prompt += f"""\n```\n{output}\n```\n\n"""
    return finish_prompt(prompt, question)


def strip_colors(text):
    ## Now remove all ANSI color codes from the prompt
    return re.sub(r"\x1b[^m]*m", "", text)


def finish_prompt(prompt, question):
    ## If the context hasn't changed, include the last question and answer
    ## (we could add more of these, but there are length limitations on prompts)
    for (q, a) in zip(LAST_QUESTION, LAST_ANSWER):
        prompt += f"""Question: {q}\n\nAnswer: {a}\n\n"""

    prompt += f"""Question: {question}

Answer: """

    prompt = strip_colors(prompt)

    return prompt


def query_openai(prompt, model="text-davinci-003", max_tokens=100, temperature=0.0):
    response = openai.Completion.create(
        engine=model.strip("\"' "),
        prompt=prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=["Question:"],
    )
    return response.choices[0].text


parser = argparse.ArgumentParser(
    description="Ask GPT-3 a question about the current debugging context."
)
parser.add_argument("question", nargs="+", type=str, help="The question to ask.")
parser.add_argument(
    "-M", "--model", default="text-davinci-003", type=str, help="The OpenAI model to use."
)
parser.add_argument("-t", "--temperature", default=0.5, type=float, help="The temperature to use.")
parser.add_argument(
    "-m", "--max-tokens", default=128, type=int, help="The maximum number of tokens to generate."
)
parser.add_argument("-v", "--verbose", action="store_true", help="Print the prompt and response.")
parser.add_argument(
    "-c",
    "--command",
    type=str,
    default=None,
    help="Run a command in the GDB debugger and ask a question about the output.",
)


@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser, command_name="ai", category=CommandCategory.INTEGRATIONS)
def ai(question, model, temperature, max_tokens, verbose, command=None) -> None:
    # print the arguments
    global LAST_QUESTION, LAST_ANSWER, LAST_PC, LAST_COMMAND
    if not OPENAI_API_KEY:
        print("Please set the OPENAI_API_KEY environment variable.")
        return
    question = " ".join(question).strip()
    current_pc = gdb.execute("info reg $pc", to_string=True)
    if current_pc == LAST_PC and command is None:
        command = LAST_COMMAND
    else:
        LAST_COMMAND = command
    if LAST_PC != current_pc or LAST_COMMAND != command:
        LAST_QUESTION.clear()
        LAST_ANSWER.clear()

    prompt = build_prompt(question, command)
    if verbose:
        print(f"Sending this prompt to OpenAI:\n\n{prompt}")
    res = query_openai(prompt, model=model, max_tokens=max_tokens, temperature=temperature).strip()
    LAST_QUESTION.append(question)
    LAST_ANSWER.append(res)
    LAST_PC = current_pc
    if len(LAST_QUESTION) > HISTORY_LENGTH:
        LAST_QUESTION.pop(0)
        LAST_ANSWER.pop(0)
    print(res)
    return
