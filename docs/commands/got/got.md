



# got

## Description


Show the state of the Global Offset Table.

Examples:
    got
    got puts
    got -p libc
    got -a

## Usage:


```bash
usage: got [-h] [-p PATH_FILTER | -a] [-r] [symbol_filter]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`symbol_filter`|Filter results by symbol name. (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-p`|`--path`|``|Filter results by library/objfile path. (default: %(default)s)|
|`-a`|`--all`||Process all libs/obfjiles including the target executable. (default: %(default)s)|
|`-r`|`--show-readonly`||Also display read-only entries (which are filtered out by default). (default: %(default)s)|
