



# spray

## Description


Spray memory with cyclic() generated values
## Usage:


```bash
usage: spray [-h] [--value VALUE] [-x] addr [length]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Address to spray|
|`length`|Length of byte sequence, when unspecified sprays until the end of vmmap which address belongs to (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
||`--value`|`None`|Value to spray memory with, when prefixed with '0x' treated as hex string encoded big-endian|
|`-x`|`--only-funcptrs`||Spray only addresses whose values points to executable pages (default: %(default)s)|
