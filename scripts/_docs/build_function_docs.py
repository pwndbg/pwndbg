"""
If the PWNDBG_DOCGEN_VERIFY environment variable
is set, then    : Exit with non-zero exit status if the docs/functions/ files
                  aren't up to date with the sources. Don't modify anything.

If it isn't, this fixes up the docs/functions/ files to be up
to date with the information from the sources.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from typing import Dict
from typing import Tuple

from mdutils.mdutils import MdUtils

from scripts._docs.function_docs_common import BASE_PATH
from scripts._docs.function_docs_common import ExtractedFunction
from scripts._docs.function_docs_common import extracted_filename
from scripts._docs.gen_docs_generic import ALL_DEBUGGERS
from scripts._docs.gen_docs_generic import update_files_simple
from scripts._docs.gen_docs_generic import verify_existence
from scripts._docs.gen_docs_generic import verify_files_simple

INTRO_TEXT = """
Pwndbg provides a set of functions which can be used during expression evaluation to
quickly perform common calculations. These can even be passed to other commands as arguments.
Currently, they **only work in gdb**.

To see a list of all functions, including those built into GDB, use `help function`. To see
the help of any given function use `help function function_name`. Function invocation must
include a preceding $ sign and must include brackets. For instance, invoke the `environ`
function like so:
```
pwndbg> p $environ("LANG")
$2 = (signed char *) 0x7fffffffe6da "LANG=en_US.UTF-8"
```
If the result of the function is being passed to a Pwndbg command, make sure to either escape
the function argument's quotes, or put the whole function call in quotes.
```
pwndbg> tele $environ("LANG")
usage: telescope [-h] [-r] [-f] [-i] [address] [count]
telescope: error: argument address: debugger couldn't resolve argument '$environ(LANG)':
    No symbol "LANG" in current context.
pwndbg> tele $environ(\\"LANG\\")
00:0000│  0x7fffffffe6cf ◂— 'LANG=en_US.UTF-8'
01:0008│  0x7fffffffe6d7 ◂— 'US.UTF-8'
02:0010│  0x7fffffffe6df ◂— 0x4e49475542454400
[...]
pwndbg> tele '$environ("LANG")'
00:0000│  0x7fffffffe6cf ◂— 'LANG=en_US.UTF-8'
01:0008│  0x7fffffffe6d7 ◂— 'US.UTF-8'
02:0010│  0x7fffffffe6df ◂— 0x4e49475542454400
[...]
```
## Pwndbg functions
""".strip()


def get_signature_markdown(func: ExtractedFunction, debugger: str):
    func_signature_code = f"""
``` {{.python .no-copy}}
{func.name}{func.signature}
```
"""
    if (
        " object at " in func.signature or "<" in func.signature
    ):  # '>' is valid in type annotation (->)
        print(f'Signature of {func.name} (from {debugger}) is rendered as "{func.signature}",')
        print("please edit the sanitize_signature() function (in the extractor) to display")
        print("the signature better in the docs.")
        sys.exit(5)

    return func_signature_code


def convert_to_markdown(extracted: list[Tuple[str, list[ExtractedFunction]]]) -> Dict[str, str]:
    """
    Returns:
        A dict which maps filenames to their markdown contents.
        It will have only one item (the index.md).
    """
    markdowned = {}

    mdFile = MdUtils(INDEX_PATH)
    mdFile.new_header(level=1, title="Functions")
    mdFile.new_paragraph(INTRO_TEXT)

    all_functions: set[str] = set()
    for _, funcs in extracted:
        all_functions.update([func.name for func in funcs])

    for func_name in sorted(all_functions):
        # Make a (debugger name, function) list in case some
        # debuggers disagree on what some function should
        # display. We won't add debuggers that don't have the
        # function.
        func_variants: list[Tuple[str, ExtractedFunction]] = []

        for debugger, dfuncs in extracted:
            # Slow but whatever
            for dfunc in dfuncs:
                if func_name == dfunc.name:
                    func_variants.append((debugger, dfunc))

        assert func_variants

        mdFile.new_paragraph(f"### **{func_name}**")
        # NOTE: We aren't saying anything about supported
        # debuggers since all functions only work in gdb for now.

        debuggers_agree = all(x[1] == func_variants[0][1] for x in func_variants)

        if debuggers_agree:
            mdFile.new_paragraph(get_signature_markdown(func_variants[0][1], debugger))
            mdFile.new_paragraph(func_variants[0][1].docstring.replace("Example:", "#### Example"))
        else:
            for debugger, dfunc in sorted(func_variants):
                # Content tabs
                # https://squidfunk.github.io/mkdocs-material/reference/content-tabs/
                mdFile.write(f'\n=== "{debugger.upper()}"')

                sig = get_signature_markdown(dfunc, debugger)
                sig = textwrap.indent(sig, "    ")
                mdFile.new_paragraph(sig)

                docs = dfunc.docstring.replace("Example:", "#### Example")
                docs = textwrap.indent(docs, "    ")
                mdFile.new_paragraph(docs)

        mdFile.new_paragraph("----------")

    hide_nav = "---\nhide:\n  - navigation\n---\n"
    autogen_warning = (
        "<!-- THIS WHOLE FILE IS AUTOGENERATED. DO NOT MODIFY IT. See scripts/generate-docs.sh -->"
    )
    markdowned[INDEX_PATH] = hide_nav + autogen_warning + "\n" + mdFile.get_md_text()
    return markdowned


def read_extracted() -> list[Tuple[str, list[ExtractedFunction]]]:
    """
    Read json files from disk.

    Returns:
        A list of tuples of the form: (debugger name, list of
        convenience functions that debugger supports).
    """

    result: list[Tuple[str, list[ExtractedFunction]]] = []

    for debugger in ALL_DEBUGGERS:
        filepath = extracted_filename(debugger)
        print(f"Consuming {filepath}..")

        with open(filepath, "r") as file:
            raw_data = json.loads(file.read())

        # Convert the dict objs to ExtractedFunction
        data = [ExtractedFunction(**func) for func in raw_data]

        result.append((debugger, data))

        # We consumed the temporary file, we can delete it now.
        os.remove(filepath)

    return result


INDEX_PATH = os.path.join(BASE_PATH, "index.md")


def main():
    if len(sys.argv) > 1:
        print("This script doesn't accept any arguments.")
        print("See top of the file for usage.")
        sys.exit(1)

    just_verify = False
    if os.getenv("PWNDBG_DOCGEN_VERIFY"):
        just_verify = True

    print("\n==== Function Documentation ====")

    extracted = read_extracted()
    markdowned = convert_to_markdown(extracted)
    assert len(markdowned) == 1  # Only index.md

    if just_verify:
        print("Checking if all files are in place..")
        missing, extra = verify_existence(list(markdowned.keys()), BASE_PATH)
        if missing or extra:
            print("To add mising files please run ./scripts/generate-docs.sh.")
            print("To remove extra files please remove them manually.")
            sys.exit(2)
        print("Every file is where it should be!")

        print("Verifying contents...")
        err = verify_files_simple(markdowned)
        if err:
            print("VERIFICATION FAILED. The files differ from what would be auto-generated.")
            print("Error:", err)
            print("Please run ./scripts/generate-docs.sh from project root and commit the changes.")
            sys.exit(3)

        print("Verification successful!")
    else:
        print("Updating files...")
        update_files_simple(markdowned)
        print("Update successful.")

        missing, extra = verify_existence(list(markdowned.keys()), BASE_PATH)
        assert (
            not missing
            and "Some files (and not the index) are missing, which should be impossible."
        )

        if extra:
            print("Please delete the extra files by hand.")
            sys.exit(4)


if __name__ == "__main__":
    main()
