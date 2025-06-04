#!/usr/bin/env python
"""
Transform the README.md to look good on the
documentation page.
"""

from __future__ import annotations

hide_nav = """---
hide:
  - navigation
---
"""

gif = """
<video autoplay loop muted playsinline alt='pwndbg gif'>
  <source src='assets/videos/demo.webm' type='video/webm'>
  <source src='assets/videos/demo.mp4' type='video/mp4'>
</video>
"""


def main():
    README_PATH = "README.md"
    TARGET_PATH = "./docs/index.md"

    with open(README_PATH, "r") as readmefile:
        readme = readmefile.read()

        assert (
            readme.splitlines()[0].startswith("![repository-open-graph](")
            and "The first line of the README.md has changed. Is it still safe to replace it?"
        )

        # Delete the first line
        readme = readme.split("\n", 1)[1]

        # Hide navigation on the doc page
        preamble = hide_nav
        # Add logo
        preamble += "\n![logo](assets/logo2.png){ style='width: 100%'}\n"

        readme = preamble + readme

        # Add gif after first paragraph
        assert "## Why?" in readme
        readme = readme.replace("## Why?\n", gif + "\n## Why?\n")

        # Write to target file.
        with open(TARGET_PATH, "w") as docsindex:
            docsindex.write(readme)


if __name__ == "__main__":
    main()
