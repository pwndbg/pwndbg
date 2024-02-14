



# probeleak

## Description



Pointer scan for possible offset leaks.
Examples:
    probeleak $rsp 0x64 - leaks 0x64 bytes starting at stack pointer and search for valid pointers
    probeleak $rsp 0x64 --max-dist 0x10 - as above, but pointers may point 0x10 bytes outside of memory page
    probeleak $rsp 0x64 --point-to libc --max-ptrs 1 --flags rwx - leaks 0x64 bytes starting at stack pointer and search for one valid pointer which points to a libc rwx page

## Usage:


```bash
usage: probeleak [-h] [--max-distance MAX_DISTANCE] [--point-to POINT_TO] [--max-ptrs MAX_PTRS] [--flags FLAGS] [address] [count]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`address`|Leak memory address (default: %(default)s)|
|`count`|Leak size in bytes (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
||`--max-distance`|`0`|Max acceptable distance between memory page boundary and leaked pointer (default: %(default)s)|
||`--point-to`|`None`|Mapping name of the page that you want the pointers point to|
||`--max-ptrs`|`0`|Stop search after find n pointers, default 0 (default: %(default)s)|
||`--flags`|`None`|flags of the page that you want the pointers point to. [e.g. rwx]|
