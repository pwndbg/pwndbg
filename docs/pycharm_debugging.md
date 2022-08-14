Debugging with PyCharm
======================

In order to debug code with PyCharm you need to configure [remote debugging](https://www.jetbrains.com/help/pycharm/remote-debugging-with-product.html#remote-interpreter).

PyCharm will start a remote debugging server which will listen for connections
and pwndbg will then connect to that server, on startup.

Configuring the debugging server
--------------------------------

Select `Run -> Edit Configurations` and follow the instructions there :)

* Create a new server with the `+` button.
* Put your IP in `IDE host name` and select a port number.
* Optionally, add a path mapping: `pycharm/pwndbg/dir=machine/pwndbg/dir`
* Uncheck `suspend after connect`

Configuring pwndbg
------------------

* Select `Run -> Edit Configurations` and install the packages described in that
window.
* `pip install pydevd-pycharm~=<your_pycharm_version>`
* Add the following code somewhere where it will execute on gdb startup:
```python
import pydevd_pycharm
pydevd_pycharm.settrace('<your_IP>', port=<port>, stdoutToServer=True, stderrToServer=True)
```

Debugging
---------

1. Start the debugging server in PyCharm
2. Run pwndbg

WSL2
----

In order to debug using WSL2, you need to obtain your Windows IP.
The easiest way to do that is to run:
```
cat /etc/resolv.conf
```
and then to pick the value in the `nameserver` line.
Then use that IP in the `IDE host name` field, when configuring the server.
Afterwards, use the same IP in `pydevd_pycharm.settrace(...)`
