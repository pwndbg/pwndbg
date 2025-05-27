#!/usr/bin/env python
"""
If the PWNDBG_DOCGEN_VERIFY environment variable
is set, then    : Exit with non-zero exit status if the docs/configuration/ files
                  aren't up to date with the sources. Don't modify anything.

If it isn't, this fixes up the docs/configuration/ files to be up
to date with the information from the sources. Except docs/configuration/index.md
which is hand-written.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Dict

import pwndbg
from pwndbg.lib.config import HELP_DEFAULT_PREFIX
from pwndbg.lib.config import HELP_VALID_VALUES_PREFIX
from pwndbg.lib.config import Parameter
from scripts._docs.configuration_docs_common import ExtractedParam
from scripts._docs.configuration_docs_common import extracted_filename
from scripts._docs.gen_docs_generic import get_debugger


def extract_params() -> Dict[str, list[Parameter]]:
    """
    Returns a dictionary that maps a scope name to a list of Parameter's
    in that scope.
    """
    scope_dict: Dict[str, list[Parameter]] = {}
    parameters = pwndbg.config.params

    # Could use pwndbg.config.get_params() here but
    # we want to catch all scopes.

    for param in parameters.values():
        scope_name = param.scope.name
        if scope_name not in scope_dict:
            scope_dict[scope_name] = []
        scope_dict[scope_name].append(param)

    # Sort the parameters by name.
    for scope in scope_dict:
        scope_dict[scope].sort(key=lambda p: p.attr_name())

    assert len(scope_dict) == len(pwndbg.lib.config.Scope) and (
        "The amount of detected scopes "
        "does not match the number of scopes defined in the source."
    )

    return scope_dict


def distill_sources(scoped_params: Dict[str, list[Parameter]]) -> Dict[str, list[ExtractedParam]]:
    result: Dict[str, list[ExtractedParam]] = {}

    for scope, params in scoped_params.items():
        result[scope] = []

        for param in params:
            set_show_doc = param.set_show_doc
            # Uppercase first letter and add dot to make it look like a sentence.
            set_show_doc = set_show_doc[0].upper() + set_show_doc[1:] + "."

            assert not param.help_docstring or (
                param.help_docstring.count(HELP_DEFAULT_PREFIX) == 1
                and "The configuration generator expects to find the string "
                f"'{HELP_DEFAULT_PREFIX}' exactly once in order to perform proper bolding."
            )
            assert (
                param.help_docstring.count(HELP_VALID_VALUES_PREFIX) <= 1
                and "The configuration generator expects to find the string "
                f"'{HELP_VALID_VALUES_PREFIX}' exactly once in order to perform proper bolding."
            )

            help_docstring = param.help_docstring.replace(
                HELP_DEFAULT_PREFIX, f"**{HELP_DEFAULT_PREFIX}**"
            )
            help_docstring = help_docstring.replace(
                HELP_VALID_VALUES_PREFIX, f"**{HELP_VALID_VALUES_PREFIX}**"
            )

            result[scope].append(ExtractedParam(param.name, set_show_doc, help_docstring))

    return result


def main():
    print("\n== Extracting Configuration ==")

    debugger = get_debugger()

    scoped_params = extract_params()
    extracted = distill_sources(scoped_params)

    result = {}
    for scope, params in extracted.items():
        result[scope] = [asdict(x) for x in params]

    # Write to file.
    out_path = extracted_filename(debugger)
    with open(out_path, "w") as file:
        json.dump(result, file)

    print("== Finished Extracting Configuration ==")


# Not checking __name__ due to lldb.
main()
