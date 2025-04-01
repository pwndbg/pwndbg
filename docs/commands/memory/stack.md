



# stack

## Description


Dereferences on stack data with specified count and offset.
## Usage:


```bash
usage: stack [-h] [-f] [-i] [count] [offset]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`count`|number of element to dump (default: %(default)s)|
|`offset`|Element offset from $sp (support negative offset) (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-f`|`--frame`||Show the stack frame, from rsp to rbp (default: %(default)s)|
|`-i`|`--inverse`||Show reverse stack growth (default: %(default)s)|
