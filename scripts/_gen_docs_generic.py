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


def update_files_simple(filename_to_markdown: Dict[str, str]):
    """
    Fix files so they are up to date with the sources. This also
    creates new files if needed.
    """

    for filename, markdown in filename_to_markdown.items():
        print(f"Updating {filename} ..")

        # Make the folder containing the file if it doesn't exist.
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        # Simple case, just create the file and write it.
        with open(filename, "w") as file:
            file.seek(0)
            file.write(markdown)


def verify_files_simple(filename_to_markdown: Dict[str, str], skip: list[str] = []) -> str | None:
    """
    Verify all the markdown files are up to date with the sources.

    Returns:
        None if everything is up-to-date.
        A string containing the error message if something is not.
    """

    for filename, markdown in filename_to_markdown.items():
        if filename in skip:
            print(f"Skipping {filename}")
            continue

        print(f"Checking {filename} ..")

        if not os.path.exists(filename):
            return f"File {filename} does not exist."

        file_data = ""
        with open(filename, "r") as file:
            file_data = file.read()
            if file_data != markdown:
                return f"File {filename} differs from auto-generated output."

    return None
