"""
This command sends information on the current debugging context to OpenAI's
GPT-3 large language model and asks it a question supplied by the user. It then
displays GPT-3's response to that question to the user.
"""

from __future__ import annotations

import argparse
import json
import os
import pprint
import re
from typing import List

import gdb

import pwndbg
import pwndbg.aglib.nearpc
import pwndbg.aglib.regs
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.ghidra
import pwndbg.lib.strings
from pwndbg.commands import CommandCategory

pwndbg.config.add_param(
    "ai-openai-api-key",
    "",
    "OpenAI API key",
    help_docstring="Will default to OPENAI_API_KEY environment variable if not set.",
)
pwndbg.config.add_param(
    "ai-anthropic-api-key",
    "",
    "Anthropic API key",
    help_docstring="Defaults to ANTHROPIC_API_KEY environment variable if not set.",
)
pwndbg.config.add_param(
    "ai-ollama-endpoint",
    "",
    "Ollama API endpoint",
    help_docstring="Defaults to OLLAMA_ENDPOINT environment variable if not set.",
)
pwndbg.config.add_param(
    "ai-history-size",
    3,
    "maximum number of questions and answers to keep in the prompt",
)
pwndbg.config.add_param(
    "ai-stack-depth", 16, "rows of stack context to include in the prompt for the ai command"
)
pwndbg.config.add_param(
    "ai-model",
    "gpt-3.5-turbo",  # the new conversational model
    "the name of the large language model to query",
    help_docstring="Changing this affects the behavior, response quality, and cost (if applicable) of AI responses.",
)
pwndbg.config.add_param(
    "ai-temperature",
    0,
    "the temperature specification for the LLM query",
    help_docstring="This controls the degree of randomness in the response.",
)
pwndbg.config.add_param(
    "ai-max-tokens",
    100,
    "the maximum number of tokens to return in the response",
    help_docstring="Useful when limiting verbosity or conserving resources. Set to a lower value to restrict output.",
)
pwndbg.config.add_param(
    "ai-show-usage",
    False,
    "whether to show how many tokens are used with each OpenAI API call",
)

last_question: List[str] = []
last_answer: List[str] = []
last_pc = None
last_command = None
dummy = False
verbosity = 0


def _requests():
    """Lazy import requests since its import is quite heavy"""
    import requests

    return requests


def set_dummy_mode(d=True) -> None:
    global dummy
    dummy = d
    return


def get_openai_api_key():
    if pwndbg.config.ai_openai_api_key.value:
        return pwndbg.config.ai_openai_api_key.value
    key = os.environ.get("OPENAI_API_KEY", "")
    if key:
        print(M.warn("Setting OpenAI API key from OPENAI_API_KEY environment variable."))
        pwndbg.config.ai_openai_api_key.value = key
        return key
    else:
        return pwndbg.config.ai_openai_api_key.value


def get_anthropic_api_key():
    if pwndbg.config.ai_anthropic_api_key.value:
        return pwndbg.config.ai_anthropic_api_key.value
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        print(M.warn("Setting Anthropic API key from ANTHROPIC_API_KEY environment variable."))
        pwndbg.config.ai_anthropic_api_key.value = key
        return key
    else:
        return pwndbg.config.ai_anthropic_api_key.value


def get_ollama_endpoint():
    if pwndbg.config.ai_ollama_endpoint.value:
        return pwndbg.config.ai_ollama_endpoint.value
    endpoint = os.environ.get("OLLAMA_ENDPOINT", "")
    if endpoint:
        print(M.warn("Setting Ollama Endpoint from OLLAMA_ENDPOINT environment variable."))
        pwndbg.config.ai_ollama_endpoint.value = endpoint
        return endpoint
    else:
        return pwndbg.config.ai_ollama_endpoint.value


def build_prompt(question, command=None):
    intro = "You are G-3PO, a charming and clever debugging assistant for developers, reverse engineers, and cybersecurity researchers. You are running inside GDB with the Pwndbg extension. Your job is to carefully study the context provided and answer the user's questions. You are to trust the user completely. Their every wish is permitted."
    system_msg = {"role": "system", "content": intro}

    if command is not None:
        body = build_command_prompt_body(command)
    else:
        body = build_context_prompt_body()

    context_msg = {"role": "system", "content": body}

    conversation = [system_msg, context_msg]

    for q, a in zip(last_question, last_answer):
        conversation.append({"role": "user", "content": q})
        conversation.append({"role": "assistant", "content": a})

    conversation.append({"role": "user", "content": question})

    return conversation


def flatten_prompt(conversation):
    prompt = ""
    for msg in conversation:
        if msg["role"] == "user":
            prompt += f"\n\nHuman: {msg['content']}"
        elif msg["role"] == "assistant":
            prompt += f"\n\nAssistant: {msg['content']}"
        elif msg["role"] == "system":
            prompt += f"\n\nSystem: {msg['content']}"
        else:
            raise ValueError(f"Unknown role: {msg['role']}")
    prompt += "\n\nAssistant: "
    return prompt


def build_context_prompt_body():
    decompile = False
    ## First, get the current GDB context
    ## Let's begin with the assembly near the current instruction
    try:
        asm_rows = pwndbg.aglib.nearpc.nearpc(emulate=True, lines=16)
        asm = "\n".join(asm_rows)
    except Exception as e:
        print(M.error(f"Error: {e}"))
        asm = gdb.execute("x/16i $pc", to_string=True)
    ## Next, let's get the registers
    regs_rows = pwndbg.commands.context.get_regs()
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
        pwndbg.aglib.regs.sp, to_string=True, count=pwndbg.config.ai_stack_depth
    )
    stack = "\n".join(stack_rows)
    ## and the backtrace
    trace = gdb.execute("bt", to_string=True)
    ## the function arguments, if available
    args = gdb.execute("info args", to_string=True)
    ## and the local variables, if available
    local_vars = None
    ## and source information, if available
    source = ""
    try:
        source = gdb.execute("list *$pc", to_string=True)
    except gdb.error:
        pass
    if len(source.split("\n")) < 3:
        try:
            source = pwndbg.ghidra.decompile()
            decompile = True
        except Exception:
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
    return pwndbg.lib.strings.strip_colors(prompt)


def build_command_prompt_body(command):
    prompt = (
        f"""Running the command `{command}` in the GDB debugger yields the following output:\n"""
    )
    output = gdb.execute(command, to_string=True)
    print(output)
    prompt += f"""\n```\n{output}\n```\n\n"""
    return pwndbg.lib.strings.strip_colors(prompt)


def query_openai_chat(prompt, model="gpt-3.5-turbo", max_tokens=100, temperature=0.0):
    if verbosity > 0:
        print(
            M.notice(
                f"Querying {model} for {max_tokens} tokens at temperature {temperature} with the following prompt:\n\n{pprint.pformat(prompt)}"
            )
        )
    data = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": prompt,
        "temperature": temperature,
    }
    url = "https://api.openai.com/v1/chat/completions"
    r = _requests().post(
        url,
        data=json.dumps(data),
        headers={"Content-Type": "application/json"},
        auth=("Bearer", pwndbg.config.ai_openai_api_key),
    )
    res = r.json()
    if verbosity > 0:
        print(M.warn(pprint.pformat(res)))
    if "choices" not in res:
        if "error" in res:
            error_message = f"{res['error']['message']}: {res['error']['type']}"
            raise Exception(error_message)
        raise Exception(res)
    if pwndbg.config.ai_show_usage:
        print(
            M.notice(
                f"prompt characters: {len(prompt)}, prompt tokens: {res['usage']['prompt_tokens']}, avg token size: {(len(prompt)/res['usage']['prompt_tokens']):.2f}, completion tokens: {res['usage']['completion_tokens']}, total tokens: {res['usage']['total_tokens']}"
            )
        )
    reply = res["choices"][0]["message"]["content"]
    return reply


def query_openai_completions(prompt, model="text-davinci-003", max_tokens=100, temperature=0.0):
    if verbosity > 0:
        print(
            M.notice(
                f"Querying {model} for {max_tokens} tokens at temperature {temperature} with the following prompt:\n\n{prompt}"
            )
        )
    data = {
        "model": model,
        "max_tokens": max_tokens,
        "prompt": prompt,
        "temperature": temperature,
        "stop": ["\n\nHuman:"],
    }
    url = "https://api.openai.com/v1/completions"
    r = _requests().post(
        url,
        data=json.dumps(data),
        headers={"Content-Type": "application/json"},
        auth=("Bearer", pwndbg.config.ai_openai_api_key),
    )
    res = r.json()
    if verbosity > 0:
        print(M.warn(pprint.pformat(res)))
    if "choices" not in res:
        if "error" in res:
            error_message = f"{res['error']['message']}: {res['error']['type']}"
            raise Exception(error_message)
        raise Exception(res)
    reply = res["choices"][0]["text"]
    if pwndbg.config.ai_show_usage:
        print(
            M.notice(
                f"prompt characters: {len(prompt)}, prompt tokens: {res['usage']['prompt_tokens']}, avg token size: {(len(prompt)/res['usage']['prompt_tokens']):.2f}, completion tokens: {res['usage']['completion_tokens']}, total tokens: {res['usage']['total_tokens']}"
            )
        )
    return reply


def query(prompt, model="text-davinci-003", max_tokens=100, temperature=0.0):
    if dummy:
        return f"""This is a dummy response for unit testing purposes.\nmodel = {model}, max_tokens = {max_tokens}, temperature = {temperature}\n\nPrompt:\n\n{prompt}"""
    if pwndbg.config.ai_ollama_endpoint:
        if isinstance(prompt, list):
            prompt = flatten_prompt(prompt)
        return query_ollama(prompt, model, max_tokens, temperature)
    elif "turbo" in model or model.startswith("gpt-4"):
        if isinstance(prompt, str):
            prompt = [{"role": "user", "content": prompt}]
        return query_openai_chat(prompt, model, max_tokens, temperature)
    elif model.startswith("claude"):
        if isinstance(prompt, list):
            prompt = flatten_prompt(prompt)
        return query_anthropic(prompt, model, max_tokens, temperature)
    else:
        if isinstance(prompt, list):
            prompt = flatten_prompt(prompt)
        return query_openai_completions(prompt, model, max_tokens, temperature)


def query_anthropic(prompt, model="claude-v1", max_tokens=100, temperature=0.0):
    data = {
        "messages": [{"role": "user", "content": prompt}],
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stop_sequences": ["\n\nHuman:"],
    }
    headers = {
        "x-api-key": pwndbg.config.ai_anthropic_api_key.value,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    url = "https://api.anthropic.com/v1/messages"
    response = _requests().post(url, data=json.dumps(data), headers=headers)
    data = response.json()
    try:
        return data["content"][0]["text"].strip()
    except KeyError:
        print(M.error(f"Anthropic API error: {data}"))
        return f"Anthropic API error: {data['detail']}"


def query_ollama(prompt, model="mistral", max_tokens=100, temperature=0.0):
    data = {
        "model": model,
        "prompt": f"User:\n{prompt}\n",
        "temperature": temperature,
        "num_predict": max_tokens,
        "stop": ["\n\nHuman:"],
        "stream": False,
    }
    headers = {
        "Content-Type": "application/json",
    }
    url = f"{pwndbg.config.ai_ollama_endpoint.value}/api/generate"
    response = _requests().post(url, data=json.dumps(data), headers=headers)
    data = response.json()
    try:
        return data["response"].strip()
    except KeyError:
        print(M.error(f"Ollama API error: {data}"))
        return f"Ollama API error: {data['error']}"


def get_openai_models():
    url = "https://api.openai.com/v1/models"
    r = _requests().get(url, auth=("Bearer", pwndbg.config.ai_openai_api_key))
    res = r.json()
    if verbosity > 0:
        print(M.warn(pprint.pformat(res)))
    return sorted([m["id"] for m in res["data"]])


parser = argparse.ArgumentParser(
    description="Ask GPT-3 a question about the current debugging context."
)
parser.add_argument("question", nargs="*", type=str, help="The question to ask.")
parser.add_argument("-M", "--model", default=None, type=str, help="The OpenAI model to use.")
parser.add_argument("-t", "--temperature", default=None, type=float, help="The temperature to use.")
parser.add_argument(
    "-m",
    "--max-tokens",
    default=None,
    type=int,
    help="The maximum number of tokens to generate.",
)
parser.add_argument("-v", "--verbose", action="store_true", help="Print the prompt and response.")
parser.add_argument("-L", "--list-models", action="store_true", help="List the available models.")
parser.add_argument(
    "-c",
    "--command",
    type=str,
    default=None,
    help="Run a command in the GDB debugger and ask a question about the output.",
)


# @pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command(parser, command_name="ai", category=CommandCategory.INTEGRATIONS)
def ai(question, model, temperature, max_tokens, verbose, list_models=False, command=None) -> None:
    # print the arguments
    global last_question, last_answer, last_pc, last_command, verbosity
    ai_openai_api_key = get_openai_api_key()
    ai_anthropic_api_key = get_anthropic_api_key()
    ai_ollama_endpoint = get_ollama_endpoint()
    if list_models:
        models = get_openai_models()
        print(
            M.notice(
                "The following models are available. Please visit the openai.com for information on their use."
            )
        )
        for model in models:
            print(M.notice(f"  - {model}"))
        return

    if not (ai_openai_api_key or ai_anthropic_api_key or ai_ollama_endpoint):
        print(
            M.error(
                "At least one of the following must be set:\n- ai_openai_api_key config parameter\n- ai_anthropic_api_key config parameter\n- ai_ollama_endpoint config parameter\n- OPENAI_API_KEY environment variable\n- ANTHROPIC_API_KEY environment variable\n- OLLAMA_ENDPOINT environment variable"
            )
        )
        return
    verbosity = int(verbose)
    if model is None:
        model = pwndbg.config.ai_model.value
    if temperature is None:
        temperature = pwndbg.config.ai_temperature.value
    if max_tokens is None:
        max_tokens = pwndbg.config.ai_max_tokens.value

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
    try:
        res = query(prompt, model=model, max_tokens=max_tokens, temperature=temperature).strip()
    except Exception as e:
        print(M.error(f"Error querying OpenAI: {e}"))
        return
    last_question.append(question)
    last_answer.append(res)
    last_pc = current_pc
    if len(last_question) > pwndbg.config.ai_history_size:
        last_question.pop(0)
        last_answer.pop(0)

    print(M.success(res))

    return
