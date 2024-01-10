



# mmap

## Description



Calls the mmap syscall and prints its resulting address.

Note that the mmap syscall may fail for various reasons
(see `man mmap`) and, in case of failure, its return value
will not be a valid pointer.

PROT values: NONE (0), READ (1), WRITE (2), EXEC (4)
MAP values: SHARED (1), PRIVATE (2), SHARED_VALIDATE (3), FIXED (0x10),
            ANONYMOUS (0x20)

Flags and protection values can be either a string containing the names of the
flags or permissions or a single number corresponding to the bitwise OR of the
protection and flag numbers.

Examples:
    mmap 0x0 4096 PROT_READ|PROT_WRITE|PROT_EXEC MAP_PRIVATE|MAP_ANONYMOUS -1 0
     - Maps a new private+anonymous page with RWX permissions at a location
       decided by the kernel.

    mmap 0x0 4096 PROT_READ MAP_PRIVATE 10 0
     - Maps 4096 bytes of the file pointed to by file descriptor number 10 with
       read permission at a location decided by the kernel.

    mmap 0xdeadbeef 0x1000
     - Maps a new private+anonymous page with RWX permissions at a page boundary
       near 0xdeadbeef.

## Usage:


```bash
usage: mmap [-h] [--quiet] [--force] addr length [prot] [flags] [fd] [offset]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Address hint to be given to mmap.|
|`length`|Length of the mapping, in bytes. Needs to be greater than zero.|
|`prot`|Prot enum or int as in mmap(2). Eg. "PROT_READ\|PROT_EXEC" or 7 (for RWX). (default: %(default)s)|
|`flags`|Flags enum or int as in mmap(2). Eg. "MAP_PRIVATE\|MAP_ANONYMOUS" or 0x22. (default: %(default)s)|
|`fd`|File descriptor of the file to be mapped, or -1 if using MAP_ANONYMOUS. (default: %(default)s)|
|`offset`|Offset from the start of the file, in bytes, if using file based mapping. (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-q`|`--quiet`||Disable address validity warnings and hints (default: %(default)s)|
|`-f`|`--force`||Force potentially unsafe actions to happen (default: %(default)s)|
