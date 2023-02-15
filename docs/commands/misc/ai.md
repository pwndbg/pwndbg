## Command ai ##
```
usage: ai [-h] [-M MODEL] [-t TEMPERATURE] [-m MAX_TOKENS] [-v] [-c COMMAND] <QUESTION>
```

| Positional Argument | Info |
|---------------------|------|
| QUESTION | The question you want to ask GPT-3 about the current context or command output. |

| Optional Argument | Info |
|-------------------|------|
| -h | show a help message |
| -M MODEL | specify which language model GPT-3 should use (default: text-davinci-003) |
| -t TEMPERATURE | set the temperature for the response, between 0.0 and 2.0, with higher temperatures provoking more 'adventurous' responses |
| -m MAX\_TOKENS | set the size of the response in token count, but note that there is a limit of 4096 tokens for the prompt and response combined, and a token is about 3 characters on average |
| -v | verbose mode -- show the prompt as well as the response |
| -c COMMAND | instead of asking about the context, run a gdb command and ask about its output |


If you have the [`openai`](https://github.com/openai/openai-python) Python
module installed, and the `OPENAI_API_KEY` environment variable set to a valid
OpenAI API key, then the `ai` command can be used to query the GPT-3 large
language model for insights into the current debugging context. The register
state, the stack, and the nearby assembly instructions will be made visible
to the model, along with the nearby source code, if the binary was compiled
with debugging information.


### Examples ###

```
pwndbg> ai what was the name of the function most recently called?
 strcmp

pwndbg> ai how do you know this?
 The assembly code shows that the function call 0x7ffff7fea240 <strcmp> was made just before the current instruction at 0x7ffff7fce2a7 <check_match+103>.

pwndbg> ai what will the next two instructions do the the eax and ecx registers?

 The next two instructions will move the values stored in the esi and edi registers into the eax and ecx registers, respectively.

pwndbg> ai say that again but as a limerick

The eax and ecx registers will fill
With the values stored in esi and edi still
The instructions will move
Their values to improve
And the registers will have a new thrill

```
