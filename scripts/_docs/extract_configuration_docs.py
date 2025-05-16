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

import os
import sys
from typing import Dict

from mdutils.mdutils import MdUtils

import pwndbg
from pwndbg.lib.config import HELP_DEFAULT_PREFIX
from pwndbg.lib.config import HELP_VALID_VALUES_PREFIX
from pwndbg.lib.config import Parameter
from scripts._docs.gen_docs_generic import update_files_simple
from scripts._docs.gen_docs_generic import verify_existence
from scripts._docs.gen_docs_generic import verify_files_simple


def extract_params() -> Dict[str, list[Parameter]]:
    """
    Returns a dictionary that maps a scope name to a list of Parameter's
    in that scope.
    """
    scope_dict: Dict[str, list[Parameter]] = {}
    parameters = pwndbg.config.params

    # could use pwndbg.config.get_params() here but whatever

    for param in parameters.values():
        scope_name = param.scope.name
        if scope_name not in scope_dict:
            scope_dict[scope_name] = []
        scope_dict[scope_name].append(param)

    # Sort the parameters by name
    for scope in scope_dict:
        scope_dict[scope].sort(key=lambda p: p.attr_name())

    assert len(scope_dict) == len(pwndbg.lib.config.Scope) and (
        "The amount of detected scopes "
        "does not match the number of scopes defined in the source."
    )

    return scope_dict

base_path = "docs/configuration/"  # Must have trailing slash.

scoped_params = extract_params()
