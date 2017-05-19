#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import pwndbg.wrappers

from pwndbg.wrappers import file_path

@pwndbg.wrappers.OnlyWithFile(file_path)
def is_statically_linked():
        if "statically" in subprocess.check_output([file_path,pwndbg.file.get_file(pwndbg.proc.exe)]).decode('utf-8'):
            return True
        else:
            return False