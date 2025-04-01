



# mprotect

## Description



Calls the mprotect syscall and prints its result value.

Note that the mprotect syscall may fail for various reasons
(see `man mprotect`) and a non-zero error return value
can be decoded with the `errno <value>` command.

Examples:
    mprotect $rsp 4096 PROT_READ|PROT_WRITE|PROT_EXEC
    mprotect some_symbol 0x1000 PROT_NONE

## Usage:


```bash
usage: mprotect [-h] addr length prot

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Page-aligned address to all mprotect on.|
|`length`|Count of bytes to call mprotect on. Needs to be multiple of page size.|
|`prot`|Prot string as in mprotect(2). Eg. "PROT_READ\|PROT_EXEC"|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
