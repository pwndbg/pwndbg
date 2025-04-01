



# vis_heap_chunks

## Description


Visualize chunks on a heap.

Default to the current arena's active heap.
## Usage:


```bash
usage: vis_heap_chunks [-h] [--beyond_top] [--no_truncate] [--all_chunks] [count] [addr]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`count`|Number of chunks to visualize. If the value is big enough and addr isn't provided, this is interpreted as addr instead. (default: %(default)s)|
|`addr`|Address of the first chunk.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-b`|`--beyond_top`||Attempt to keep printing beyond the top chunk. (default: %(default)s)|
|`-n`|`--no_truncate`||Display all the chunk contents (Ignore the `max-visualize-chunk-size` configuration). (default: %(default)s)|
|`-a`|`--all_chunks`|| Display all chunks (Ignore the default-visualize-chunk-number configuration). (default: %(default)s)|
