# IDA

## Usage
Open the same binary with Pwndbg and IDA. Then inside IDA go to `File > Script file` and select the `ida_script.py` file from the Pwndbg root folder. This will start the XMLRPC server that Pwndbg queries for information.

Inside the debugger, run `set integration-provider ida`. This will start the integration, you can run `set integration-provider none` to disable it.

## Features
The integration will sync IDA's decompilation and show it in the context. You can query for symbols and stack variables using the [`ida`](../../functions/index.md#ida) function.

## Debugger Control
To see an up-to-date list of things you can do regarding IDA integration, you may grep for `ida` like so:
```
pwndbg> pwndbg ida
find-fake-fast                             Find candidate fake fast or tcache chunks overlapping the specified address.
save-ida                           Save the ida database.
pwndbg> config ida
attachp-resolution-method          how to determine the process to attach when multiple candidates exists   'ask'
ida-rpc-host                       ida xmlrpc server address                                                '127.0.0.1'
ida-rpc-port                       ida xmlrpc server port                                                   31337
ida-timeout                        time to wait for ida xmlrpc in seconds                                   2
pwndbg> | help function | grep ida
function ida -- Lookup a symbol's address by name from IDA.
```
Note that you will see some false positives.

You can use the [`decomp`](../../commands/integrations/decomp.md) command to use IDA to decompile at an arbitrary address.
