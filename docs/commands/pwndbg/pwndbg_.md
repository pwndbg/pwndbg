



# pwndbg

## Description


Prints out a list of all pwndbg commands.
## Usage:


```bash
usage: pwndbg [-h] [--shell | --all] [-c CATEGORY_ | --list-categories] [filter_pattern]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`filter_pattern`|Filter to apply to commands names/docs|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
||`--shell`||Only display shell commands (default: %(default)s)|
||`--all`||Only display shell commands (default: %(default)s)|
|`-c`|`--category`|`None`|Filter commands by category|
||`--list-categories`||List command categories (default: %(default)s)|
