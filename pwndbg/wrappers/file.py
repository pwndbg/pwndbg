#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.wrappers

cmd_name = "file"

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def is_statically_linked():

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [is_statically_linked.cmd_path, local_path]

    file_out = pwndbg.wrappers.call_cmd(cmd)

    if "statically" in file_out:
        return True
    else:
        return False
