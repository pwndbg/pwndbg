



# heap

## Description


Iteratively print chunks on a heap.

Default to the current thread's active heap.
## Usage:


```bash
usage: heap [-h] [-v] [-s] [addr]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Address of the first chunk (malloc_chunk struct start, prev_size field).|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-v`|`--verbose`||Print all chunk fields, even unused ones. (default: %(default)s)|
|`-s`|`--simple`||Simply print malloc_chunk struct's contents. (default: %(default)s)|
