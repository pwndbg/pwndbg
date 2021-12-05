## Command: probeleak ##
```
usage: probeleak [-h] [address] [count] [max_distance]
```
Pointer scan for possible offset leaks. Examples: probeleak $rsp 0x64 - leaks 0x64 bytes starting at stack pointer and search for valid pointers probeleak $rsp 0x64 0x10 - as above, but pointers may point 0x10 bytes outside of memory page  

| Positional Argument | Info |
|---------------------|------|
| address | Leak memory address (default: $sp) |
| count | Leak size in bytes (default: 64) |
| max_distance | Max acceptable distance between memory page boundary and leaked pointer (default: 0) |

| Optional Argument | Info |
|---------------------|------|
| --help | show this help message and exit |


