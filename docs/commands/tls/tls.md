



# tls

## Description


Print out base address of the current Thread Local Storage (TLS).
## Usage:


```bash
usage: tls [-h] [-p]

```
## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-p`|`--pthread-self`||Try to get the address of TLS by calling pthread_self(). (default: %(default)s)|
