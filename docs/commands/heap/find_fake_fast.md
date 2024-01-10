



# find_fake_fast

## Description


Find candidate fake fast or tcache chunks overlapping the specified address.
## Usage:


```bash
usage: find_fake_fast [-h] [--align] [--glibc-fastbin-bug] target_address [max_candidate_size]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`target_address`|Address of the word-sized value to overlap.|
|`max_candidate_size`|Maximum size of fake chunks to find.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-a`|`--align`||Whether the fake chunk must be aligned to MALLOC_ALIGNMENT. This is required for tcache chunks and for all chunks when Safe Linking is enabled (default: %(default)s)|
|`-b`|`--glibc-fastbin-bug`||Does the GLIBC fastbin size field bug affect the candidate size field width? (default: %(default)s)|
