



# threads

## Description


List all threads belonging to the selected inferior.
## Usage:


```bash
usage: threads [-h] [-c] [num_threads]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`num_threads`|Number of threads to display. Omit to display all threads.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-c`|`--config`||Respect context-max-threads config to limit number of threads displayed. (default: %(default)s)|
