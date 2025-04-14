#!/usr/bin/env python
from __future__ import annotations

import os


def get_files_in_dir(directory) -> list[str]:
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, directory)
            file_paths.append(relative_path)
    return file_paths


def verify_existence(filenames: list[str], base_path: str) -> (list[str], list[str]):
    current = get_files_in_dir(base_path)
    current = [base_path + x for x in current]

    missing = [x for x in filenames if x not in current]
    extra = [x for x in current if x not in filenames]

    if missing:
        print("Missing files:")
        for f in missing:
            print(f)
        print()

    if extra:
        print("These files shouldn't exist:")
        for f in extra:
            print(f)
        print()

    return missing, extra
