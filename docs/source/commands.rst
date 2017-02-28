.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Commands
========

``pwndbg`` provides a very rich command API for interaction.

Some of the commands are listed here.

.. toctree::

.. autoprogram:: pwnlib.commandline.main:parser
   :prog: pwn
