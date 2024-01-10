



# malloc_chunk

## Description


Print a chunk.
## Usage:


```bash
usage: malloc_chunk [-h] [-f] [-v] [-s] addr

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`addr`|Address of the chunk (malloc_chunk struct start, prev_size field).|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-f`|`--fake`||Is this a fake chunk? (default: %(default)s)|
|`-v`|`--verbose`||Print all chunk fields, even unused ones. (default: %(default)s)|
|`-s`|`--simple`||Simply print malloc_chunk struct's contents. (default: %(default)s)|
