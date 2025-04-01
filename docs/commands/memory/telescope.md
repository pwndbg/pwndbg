



# telescope

## Description


Recursively dereferences pointers starting at the specified address.
## Usage:


```bash
usage: telescope [-h] [-r] [-f] [-i] [address] [count]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`address`|The address to telescope at. (default: %(default)s)|
|`count`|The number of lines to show. (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-r`|`--reverse`||Show <count> previous addresses instead of next ones (default: %(default)s)|
|`-f`|`--frame`||Show the stack frame, from rsp to rbp (default: %(default)s)|
|`-i`|`--inverse`||Show the stack reverse growth (default: %(default)s)|
