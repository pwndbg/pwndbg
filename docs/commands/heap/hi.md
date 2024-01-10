



# hi

## Description


Searches all heaps to find if an address belongs to a chunk. If yes, prints the chunk.
## Usage:


```bash
usage: hi [-h] [-v] [-s] [-f] addr

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Address of the interest.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-v`|`--verbose`||Print all chunk fields, even unused ones. (default: %(default)s)|
|`-s`|`--simple`||Simply print malloc_chunk struct's contents. (default: %(default)s)|
|`-f`|`--fake`||Allow fake chunks. If set, displays any memory as a heap chunk (even if its not a real chunk). (default: %(default)s)|
