#!/usr/bin/env python3
"""
utils.py — Shared Utilities
------------------------------
SCS003: Missing Null Check (CWE-476)

Shared constants and helper functions used across
all pipeline steps.
"""

# ─────────────────────────────────────────────
# srcML XML NAMESPACES
# Used in all XPath queries
# ─────────────────────────────────────────────
NAMESPACES = {
    "src" : "http://www.srcML.org/srcML/src",
    "cpp" : "http://www.srcML.org/srcML/cpp",
    "pos" : "http://www.srcML.org/srcML/position",
    "sec" : "security.smells"
}

# ─────────────────────────────────────────────
# KNOWN SINK FUNCTIONS for CWE-476
# Function names associated with vulnerable contexts
# in the Juliet Test Suite and common C code
# ─────────────────────────────────────────────
KNOWN_SINKS = [
    "_bad",       # Juliet Test Suite naming convention
    "bad",
    "deref",
    "use_ptr",
    "access"
]


def extract_line(location: str) -> str:
    """
    Extracts the line number from a srcSlice location string.

    srcSlice uses the format: filename.c:line:col
    e.g. 'CWE476_NULL_Pointer_Dereference__binary_if_01.c:25:14' -> '25'

    Args:
        location: location string from srcSlice JSON

    Returns:
        Line number as string
    """
    parts = location.split(":")
    if len(parts) >= 3:
        return parts[-2]
    return location