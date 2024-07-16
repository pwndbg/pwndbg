from __future__ import annotations

from capstone.sparc import *  # noqa: F403

# Instruction groups for future use
SPARC_LOAD_INSTRUCTIONS = {
    SPARC_INS_LDUB: 1,
    SPARC_INS_LDSB: 1,
    SPARC_INS_LDUH: 2,
    SPARC_INS_LDSH: 2,
    SPARC_INS_LD: 4,
    SPARC_INS_LDD: 8,
}

SPARC_STORE_INSTRUCTIONS = {
    SPARC_INS_STB: 1,
    SPARC_INS_STH: 2,
    SPARC_INS_ST: 4,
    SPARC_INS_STD: 8,
}
