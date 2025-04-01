



# ai

## Description


Ask GPT-3 a question about the current debugging context.
## Usage:


```bash
usage: ai [-h] [-M MODEL] [-t TEMPERATURE] [-m MAX_TOKENS] [-v] [-L] [-c COMMAND] [question ...]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`question`|The question to ask.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-M`|`--model`|`None`|The OpenAI model to use.|
|`-t`|`--temperature`|`None`|The temperature to use.|
|`-m`|`--max-tokens`|`None`|The maximum number of tokens to generate.|
|`-v`|`--verbose`||Print the prompt and response. (default: %(default)s)|
|`-L`|`--list-models`||List the available models. (default: %(default)s)|
|`-c`|`--command`|`None`|Run a command in the GDB debugger and ask a question about the output.|
