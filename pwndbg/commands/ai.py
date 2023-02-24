"""
This command sends information on the current debugging context to OpenAI's
GPT-3 large language model and asks it a question supplied by the user. It then
displays GPT-3's response to that question to the user.
"""

import argparse
import json
import os
import re
import textwrap

import gdb
import requests

import pwndbg
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.commands import context
from pwndbg.gdblib import config
from pwndbg.gdblib import regs as REGS

config.add_param("ai-openai-api-key", "", "OpenAI API key")
try:
    config.ai_openai_api_key = os.environ["OPENAI_API_KEY"]
except KeyError:
    pass

config.add_param(
    "ai-history-size",
    3,
    "Maximum number of successive questions and answers to maintain in the prompt for the ai command.",
)
config.add_param(
    "ai-stack-depth", 16, "Rows of stack context to include in the prompt for the ai command."
)
config.add_param(
    "ai-model",
    "text-davinci-003",
    "The name of the OpenAI large language model to query. See <https://platform.openai.com/docs/models> for details.",
)
config.add_param(
    "ai-temperature",
    0,
    "The temperature specification for the LLM query. This controls the degree of randomness in the response. See <https://beta.openai.com/docs/api-reference/parameters> for details.",
)
config.add_param(
    "ai-max-tokens",
    100,
    "The maximum number of tokens to return in the response. See <https://beta.openai.com/docs/api-reference/parameters> for details.",
)

last_question = []
last_answer = []
last_pc = None
last_command = None
dummy = False
verbosity = 0


def set_dummy_mode(d=True):
    global dummy
    dummy = d
    return


def build_prompt(question, command=None):
    if command is not None:
        return build_prompt_from_command(question, command)

    decompile = False
    ## First, get the current GDB context
    ## Let's begin with the assembly near the current instruction
    try:
        asm_rows = pwndbg.gdblib.nearpc.nearpc(emulate=True, lines=16)
        asm = "\n".join(asm_rows)
    except Exception as e:
        print(M.error(f"Error: {e}"))
        asm = gdb.execute("x/16i $pc", to_string=True)
    ## Next, let's get the registers
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
    stack_rows = pwndbg.commands.telescope.telescope(
        REGS.sp, to_string=True, count=config.ai_stack_depth
    )
    stack = "\n".join(stack_rows)
    ## and the backtrace
    trace = gdb.execute("bt", to_string=True)
    ## the function arguments, if available
    args = gdb.execute("info args", to_string=True)
    ## and the local variables, if available
    local_vars = None
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

    if asm:
        prompt += f"""These are the next assembly instructions to be executed:

```
{asm}
```

"""
    if regs:
        prompt += f"""Here are the registers, '*' indicates a recent change:

```
{regs}
```

"""
    if flags:
        prompt += f"""The flags {flags} are set.\n\n"""
    if stack:
        prompt += f"""Here is the stack:

```
{stack}
```

"""
    if trace:
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
    prompt = (
        f"""Running the command `{command}` in the GDB debugger yields the following output:\n"""
    )
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
    for (q, a) in zip(last_question, last_answer):
        prompt += f"""Question: {q}\n\nAnswer: {a}\n\n"""

    prompt += f"""Question: {question}

Answer: """

    prompt = strip_colors(prompt)

    return prompt


def query_openai(prompt, model="text-davinci-003", max_tokens=100, temperature=0.0):
    if dummy:
        return f"""This is a dummy response for unit testing purposes.\nmodel = {model}, max_tokens = {max_tokens}, temperature = {temperature}\n\nPrompt:\n\n{prompt}"""
    data = {"model": model, "max_tokens": max_tokens, "prompt": prompt, "temperature": temperature}
    host = "api.openai.com"
    path = "/v1/completions"
    url = f"https://{host}{path}"
    r = requests.post(
        url,
        data=json.dumps(data),
        headers={"Content-Type": "application/json"},
        auth=("Bearer", config.ai_openai_api_key),
    )
    res = r.json()
    if verbosity > 0:
        print(M.notice(repr(res)))
    if "choices" not in res:
        if "error" in res:
            error_message = f"{res['error']['message']}: {res['error']['type']}"
            raise Exception(error_message)
        else:
            raise Exception(res)
    else:
        return res["choices"][0]["text"]


parser = argparse.ArgumentParser(
    description="Ask GPT-3 a question about the current debugging context."
)
parser.add_argument("question", nargs="+", type=str, help="The question to ask.")
parser.add_argument(
    "-M", "--model", default=config.ai_model, type=str, help="The OpenAI model to use."
)
parser.add_argument(
    "-t", "--temperature", default=config.ai_temperature, type=float, help="The temperature to use."
)
parser.add_argument(
    "-m",
    "--max-tokens",
    default=128,
    type=config.ai_max_tokens,
    help="The maximum number of tokens to generate.",
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
    global last_question, last_answer, last_pc, last_command, verbosity
    if not config.ai_openai_api_key:
        print(
            "Please set ai_openai_api_key config parameter in your GDB init file or set the OPENAI_API_KEY environment variable"
        )
        return
    if verbose:
        verbosity = 1
    question = " ".join(question).strip()
    current_pc = gdb.execute("info reg $pc", to_string=True)
    if current_pc == last_pc and command is None:
        command = last_command
    else:
        last_command = command
    if last_pc != current_pc or last_command != command:
        last_question.clear()
        last_answer.clear()

    prompt = build_prompt(question, command)
    if verbose:
        print(M.notice(f"Sending this prompt to OpenAI:\n\n{prompt}"))
    try:
        res = query_openai(
            prompt, model=model, max_tokens=max_tokens, temperature=temperature
        ).strip()
    except Exception as e:
        print(M.error(f"Error querying OpenAI: {e}"))
        return
    last_question.append(question)
    last_answer.append(res)
    last_pc = current_pc
    if len(last_question) > config.ai_history_size:
        last_question.pop(0)
        last_answer.pop(0)

    term_width = os.get_terminal_size().columns
    answer = textwrap.fill(res, term_width)
    print(M.success(answer))

    return
