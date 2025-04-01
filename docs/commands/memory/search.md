



# search

## Description


Search memory for byte sequences, strings, pointers, and integer values.

By default search results are cached. If you want to cache all results, but only print a subset, use --trunc-out. If you want to cache only a subset of results, and print the results immediately, use --limit. The latter is specially useful if you're searching a huge section of memory.


## Usage:


```bash
usage: search [-h] [-t {byte,short,word,dword,qword,pointer,string,bytes}] [-1] [-2] [-4] [-8] [-p] [-x] [-e] [-w] [-s STEP] [-l LIMIT] [-a ALIGNED] [--save] [--no-save] [-n]
              [--trunc-out]
              value [mapping_name]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`value`|Value to search for|
|`mapping_name`|Mapping to search [e.g. libc]|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-t`|`--type`|`bytes`|Size of search target (default: %(default)s)|
|`-1`|`--byte`|`None`|Search for a 1-byte integer|
|`-2`|`--short`|`None`|Search for a 2-byte integer|
|`-4`|`--dword`|`None`|Search for a 4-byte integer|
|`-8`|`--qword`|`None`|Search for an 8-byte integer|
|`-p`|`--pointer`|`None`|Search for a pointer-width integer|
|`-x`|`--hex`||Target is a hex-encoded (for bytes/strings) (default: %(default)s)|
|`-e`|`--executable`||Search executable segments only (default: %(default)s)|
|`-w`|`--writable`||Search writable segments only (default: %(default)s)|
|`-s`|`--step`|`None`|Step search address forward to next alignment after each hit (ex: 0x1000)|
|`-l`|`--limit`|`None`|Max results before quitting the search. Differs from --trunc-out in that it will not save all search results before quitting|
|`-a`|`--aligned`|`None`|Result must be aligned to this byte boundary|
||`--save`|`None`|Save results for further searches with --next. Default comes from config 'auto-save-search'|
||`--no-save`|`None`|Invert --save|
|`-n`|`--next`||Search only locations returned by previous search with --save (default: %(default)s)|
||`--trunc-out`||Truncate the output to 20 results. Differs from --limit in that it will first save all search results (default: %(default)s)|
