#!/usr/bin/env python3
"""
step2_locate.py — XPath Sink Locator
--------------------------------------
SCS003: Missing Null Check (CWE-476)

Takes findings from Step 1 and uses XPath queries on the
srcML XML file to confirm the exact sink location.

XPath Checks:
    Check 1: Find if_stmt at the use line number
    Check 2: Confirm operator is '&' (bitwise) not '&&'
    Check 3: Confirm '->' dereference exists in same if_stmt

Input:
    tree      -- lxml parsed srcML XML tree
    finding   -- single finding dict from step1_detect

Output:
    sink result dict with XPath check results
"""

from utils import NAMESPACES, extract_line


def locate(tree, finding: dict) -> dict:
    """
    Uses XPath to locate and confirm the sink in srcML XML.

    Args:
        tree:    lxml etree parsed from srcML XML file
        finding: single finding dict from step1_detect.detect()

    Returns:
        Sink result dict with confirmed flag and XPath check results
    """
    variable = finding["variable"]
    function = finding["function"]
    used_at  = finding["used_at"]

    if not used_at:
        return None

    # extract line number from first use location
    # format: "filename.c:line:col" -> "line"
    first_use = used_at[0]
    use_line  = extract_line(first_use)

    print(f"\n  Processing  : {variable} in {function}")
    print(f"  {'-' * 40}")
    print(f"  Use location: {first_use}")
    print(f"  Line number : {use_line}\n")

    sink = {
        "variable"          : variable,
        "function"          : function,
        "cwe"               : "CWE-476",
        "use_line"          : use_line,
        "found_if_stmt"     : False,
        "found_bitwise_and" : False,
        "found_dereference" : False,
        "confirmed"         : False
    }

    # ── CHECK 1: Find if_stmt at the use line ──
    # Uses @pos:start on the if_stmt element itself
    xpath1 = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    if_stmts = tree.xpath(xpath1, namespaces=NAMESPACES)
    sink["found_if_stmt"] = len(if_stmts) > 0

    if sink["found_if_stmt"]:
        print(f"  [PASS] if_stmt found at line {use_line}")
    else:
        print(f"  [FAIL] No if_stmt found at line {use_line}")
        return sink

    # ── CHECK 2: Confirm operator is '&' not '&&' ──
    # Looks for an operator element with exact text '&'
    xpath2 = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
        f"//src:operator[.='&']"
    )
    bitwise_ops = tree.xpath(xpath2, namespaces=NAMESPACES)
    sink["found_bitwise_and"] = len(bitwise_ops) > 0

    if sink["found_bitwise_and"]:
        print(f"  [PASS] Bitwise '&' operator confirmed (not '&&')")
    else:
        print(f"  [FAIL] No bitwise '&' found — may be safe '&&'")

    # ── CHECK 3: Confirm '->' dereference exists ──
    # Looks for '->' operator inside the same if_stmt
    xpath3 = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
        f"//src:operator[.='->']"
    )
    deref_ops = tree.xpath(xpath3, namespaces=NAMESPACES)
    sink["found_dereference"] = len(deref_ops) > 0

    if sink["found_dereference"]:
        print(f"  [PASS] Pointer dereference '->' confirmed")
    else:
        print(f"  [FAIL] No '->' dereference found")

    # ── ALL 3 CHECKS MUST PASS TO CONFIRM SINK ──
    sink["confirmed"] = (
        sink["found_if_stmt"] and
        sink["found_bitwise_and"] and
        sink["found_dereference"]
    )

    return sink


def print_report(sink_results: list):
    """Prints sink location report to terminal."""
    print("\n" + "=" * 60)
    print("  CWE-476 SINK LOCATION REPORT")
    print("=" * 60)
    confirmed = sum(1 for s in sink_results if s and s["confirmed"])
    print(f"  Sinks confirmed: {confirmed} / {len(sink_results)}")
    print("=" * 60)

    for i, s in enumerate(sink_results, 1):
        if not s:
            continue
        print(f"\n  [{i}] Variable : {s['variable']}")
        print(f"      Function : {s['function']}")
        print(f"      Use line : {s['use_line']}")
        print(f"      CWE      : {s['cwe']}")
        print(f"\n      XPath Checks:")
        print(f"        {'[PASS]' if s['found_if_stmt']     else '[FAIL]'}"
              f"  if_stmt found at line {s['use_line']}")
        print(f"        {'[PASS]' if s['found_bitwise_and'] else '[FAIL]'}"
              f"  operator is '&' (bitwise, not '&&')")
        print(f"        {'[PASS]' if s['found_dereference'] else '[FAIL]'}"
              f"  '->' dereference exists")
        status = "SINK CONFIRMED ⚠️" if s["confirmed"] else "NOT confirmed"
        print(f"\n      {status}")

    print("\n" + "=" * 60 + "\n")


def save_report(sink_results: list, json_file: str, reports_dir: str):
    """
    Saves sink location report as JSON to reports_dir.

    Args:
        sink_results: list of sink dicts from locate()
        json_file:    original input JSON path (used for filename)
        reports_dir:  output directory path
    """
    import os
    import json

    os.makedirs(reports_dir, exist_ok=True)

    base_name   = os.path.basename(json_file).replace(".json", "_sink_report.json")
    report_file = os.path.join(reports_dir, base_name)

    report = {
        "cwe"         : "CWE-476",
        "smell"       : "null-pointer-dereference",
        "source_file" : json_file,
        "total_sinks" : len(sink_results),
        "confirmed"   : sum(1 for s in sink_results if s and s["confirmed"]),
        "results"     : []
    }

    for s in sink_results:
        if not s:
            continue
        report["results"].append({
            "variable"       : s["variable"],
            "function"       : s["function"],
            "cwe"            : s["cwe"],
            "use_line"       : s["use_line"],
            "sink_confirmed" : s["confirmed"],
            "xpath_checks"   : {
                "found_if_stmt"     : s["found_if_stmt"],
                "found_bitwise_and" : s["found_bitwise_and"],
                "found_dereference" : s["found_dereference"],
            }
        })

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"  Sink report saved to: {report_file}")
    return report_file