#!/usr/bin/env python3
"""
step1_detect.py — Detection Rule Engine
----------------------------------------
SCS003: Missing Null Check (CWE-476)

Reads a srcSlice JSON file and applies 4 detection rules
to identify candidate pointer variables that may be involved
in a NULL pointer dereference.

Detection Rules:
    Rule 1: type contains "*"       -> is a pointer
    Rule 2: dependence == []        -> no null check
    Rule 3: use line exists         -> pointer is used
    Rule 4: function contains sink  -> vulnerable context

Input:
    slice_json  -- path to srcSlice JSON file

Output:
    list of finding dicts
"""

from utils import KNOWN_SINKS


def detect(slice_profile: dict) -> list:
    """
    Applies 4 detection rules to srcSlice JSON profile.

    Args:
        slice_profile: parsed JSON dict from srcSlice output

    Returns:
        List of findings (dicts) for variables that pass all rules
    """
    findings = []

    for key, variable in slice_profile.items():

        name       = variable.get("name", "")
        var_type   = variable.get("type", "")
        function   = variable.get("function", "")
        filename   = variable.get("file", "")
        dependence = variable.get("dependence", [])
        use        = variable.get("use", [])
        definition = variable.get("definition", [])

        # ── RULE 1: type must contain "*" (is a pointer) ──
        rule1 = "*" in var_type

        # ── RULE 2: dependence must be empty (no null check) ──
        rule2 = len(dependence) == 0

        # ── RULE 3: use line must exist (pointer is used) ──
        rule3 = len(use) > 0

        # ── RULE 4: function name contains a known sink ──
        rule4 = any(sink in function.lower() for sink in KNOWN_SINKS)

        # ── ALL RULES MUST PASS ──
        if rule1 and rule2 and rule3 and rule4:
            findings.append({
                "variable"   : name,
                "type"       : var_type,
                "function"   : function,
                "file"       : filename,
                "defined_at" : definition,
                "used_at"    : use,
                "smell"      : "null-pointer-dereference",
                "cwe"        : "CWE-476",
                "severity"   : "HIGH",
                "rules_hit"  : {
                    "rule1_is_pointer"      : rule1,
                    "rule2_no_null_check"   : rule2,
                    "rule3_pointer_is_used" : rule3,
                    "rule4_in_known_sink"   : rule4,
                }
            })

    return findings


def print_report(findings: list, json_file: str):
    """Prints detection report to terminal."""
    print("\n" + "=" * 60)
    print("  CWE-476 DETECTION REPORT")
    print("=" * 60)
    print(f"  Input file : {json_file}")
    print(f"  Findings   : {len(findings)}")
    print("=" * 60)

    if not findings:
        print("\n  No null pointer dereference smell detected.\n")
        return

    for i, f in enumerate(findings, 1):
        print(f"\n  [{i}] SMELL DETECTED")
        print(f"  {'-' * 40}")
        print(f"  Variable  : {f['variable']}")
        print(f"  Type      : {f['type']}")
        print(f"  Function  : {f['function']}")
        print(f"  File      : {f['file']}")
        print(f"  Defined at: {', '.join(f['defined_at'])}")
        print(f"  Used at   : {', '.join(f['used_at'])}")
        print(f"  CWE       : {f['cwe']}")
        print(f"  Severity  : {f['severity']}")
        print(f"\n  Detection Rules:")
        for rule, passed in f["rules_hit"].items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"    {status}  {rule}")