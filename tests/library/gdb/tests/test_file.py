from __future__ import annotations

import os
import tempfile

from pwndbg.aglib.file import get


def test_get():
    # Test different relative and absolute file path prefixes
    cwd = os.getcwd()
    test_file_prefixes = ["/", "./", f"../{os.path.basename(cwd)}/", ""]
    with tempfile.TemporaryDirectory(dir=cwd) as tempdir:
        path = os.path.join(tempdir, "test_file")
        with open(path, "w") as f:
            f.write("test")
        for test_prefix in test_file_prefixes:
            test_path = path if test_prefix == "/" else test_prefix + os.path.relpath(path)
            assert get(test_path) == b"test"
