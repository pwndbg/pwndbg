---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

<!--
Before reporting a new issue, make sure that we do not have any duplicates already open.
If there is one it might be good to take part in the discussion there.

Please make sure you have checked that the issue persists on LATEST pwndbg version.

Below is a template for BUG REPORTS.
Don't include it if this is a FEATURE REQUEST.
-->


### Description

<!--
Briefly describe the problem you are having in a few paragraphs.
-->

### Steps to reproduce

<!--
What do we have to do to reproduce the problem?
If this is connected to particular C/asm code,
please provide the smallest C code that reproduces the issue.
-->

### My setup

<!--
Show us your gdb/python/pwndbg/OS/IDA Pro version (depending on your case).

NOTE: We are currently supporting only Ubuntu installations.
It is known that pwndbg is not fully working e.g. on Arch Linux (the heap stuff is not working there).
If you would like to change this situation - help us improving pwndbg and supporting other distros!

This can be displayed in pwndbg through `version` command.

If it is somehow unavailable, use:
* `show version` - for gdb
* `py import sys; print(sys.version)` - for python
* pwndbg version/git commit id
-->
