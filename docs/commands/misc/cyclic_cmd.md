



# cyclic

## Description


Cyclic pattern creator/finder.
## Usage:


```bash
usage: cyclic [-h] [-a charset] [-n length] [-l lookup_value | count]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`count`|Number of characters to print from the sequence (default: print the entire sequence) (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-a`|`--alphabet`|`abcdefghijklmnopqrstuvwxyz`|The alphabet to use in the cyclic pattern (default: %(default)s)|
|`-n`|`--length`|`None`|Size of the unique subsequences (defaults to the pointer size for the current arch)|
|`-o`|`--lookup`|`None`|Do a lookup instead of printing the sequence (accepts constant values as well as expressions)|
