from pathlib import Path
import mkdocs_gen_files
import os
import sys

if os.environ.get("SKIP_GENERATION"):
    sys.exit(0)


nav = mkdocs_gen_files.Nav()

for path in sorted(Path("pwndbg").rglob("*.py")):
    # TODO: fix and remove
    if 'pwndbg/lib/kernel' in str(path):
        continue

    module_path = path.relative_to(".").with_suffix("")
    doc_path = path.relative_to("pwndbg").with_suffix(".md")
    full_doc_path = Path("source", doc_path)

    parts = tuple(module_path.parts)

    if parts[-1] == "__init__":
        parts = parts[:-1]
    elif parts[-1] == "__main__":
        continue

    nav[parts] = doc_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        ident = ".".join(parts)
        fd.write(f"::: {ident}")

    mkdocs_gen_files.set_edit_path(full_doc_path, path)

with mkdocs_gen_files.open("source/index.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
