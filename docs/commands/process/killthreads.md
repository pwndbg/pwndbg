



# killthreads

## Description


Kill all or given threads.

Switches to given threads and calls pthread_exit(0) on them.
This is performed with scheduler-locking to prevent other threads from operating at the same time.

Killing all other threads may be useful to use GDB checkpoints, e.g., to test given input & restart the execution to the point of interest (checkpoint).

## Usage:


```bash
usage: killthreads [-h] [-a] [thread_ids ...]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`thread_ids`|Thread IDs to kill.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-a`|`--all`||Kill all threads except the current one. (default: %(default)s)|
