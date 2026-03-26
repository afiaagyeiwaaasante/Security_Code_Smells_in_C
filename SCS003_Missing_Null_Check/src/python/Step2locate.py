#!/usr/bin/env python3
"""
step2_locate.py — XPath Sink Locator
--------------------------------------
SCS003: Missing Null Check (CWE-476)

Takes findings from Step 1 and uses XPath queries on the
srcML XML file to confirm the exact sink location.

Supports multiple Juliet scenarios variants:

binary_if:
    Check 1: Find if_stmt at the use line number
    Check 2: Confirm operator is '&' (bitwise) not '&&'
    Check 3: Confirm '->' dereference exists in same if_stmt

char:
    Check 1: Find expr_stmt containing array index at use line
    Check 2: Confirm pointer variable is accessed via index [0]
    Check 3: Confirm NO if_stmt null guard exists before access    

Input:
    tree      -- lxml parsed srcML XML tree
    finding   -- single finding dict from step1_detect
    scenario  -- variant name e.g. "binary_if" or "char"

Output:
    sink result dict with XPath check results
"""

from utils import NAMESPACES, extract_line

# ═════════════════════════════════════════════
# SCENARIO DISPATCHER
# ═════════════════════════════════════════════
def locate(tree, finding: dict, scenario: str = "binary_if") -> dict:
    """
    Dispatches to the correct XPath locator based on scenario.
 
    Args:
        tree:     lxml etree parsed from srcML XML file
        finding:  single finding dict from step1_detect.detect()
        scenario: Juliet variant name ("binary_if" or "char")
 
    Returns:
        Sink result dict with confirmed flag and XPath check results
    """
    if scenario == "binary_if":
        return locate_binary_if(tree, finding)
    elif scenario == "char":
        return locate_char(tree, finding)
    else:
        print(f"  [ERROR] Unknown scenario: {scenario}")
        return None
# ═════════════════════════════════════════════
# VARIANT 1 — binary_if
# Sink: bitwise & in if condition with -> dereference
# ═════════════════════════════════════════════
def locate_binary_if(tree, finding: dict) -> dict:
    """
    Locates sink for the binary_if variant.
 
    Bad pattern:
        if ((ptr != NULL) & (ptr->intOne == 5))
                         ^
                         bitwise & evaluates both sides
                         causing NPD when ptr is NULL
 
    XPath Checks:
        Check 1: if_stmt exists at use line
        Check 2: operator '&' exists (not '&&')
        Check 3: operator '->' exists (pointer dereference)
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
        "scenario"          : "binary_if",
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

# ═════════════════════════════════════════════
# VARIANT 2 — char
# Sink: direct array access data[0] on NULL pointer
# with no null guard before it
# ═════════════════════════════════════════════
def locate_char(tree, finding: dict) -> dict:
    """
    Locates sink for the char variant.
 
    Bad pattern:
        char * data = NULL;
        printHexCharLine(data[0]);  <- SINK: no null check before access
 
    Good patterns:
        goodG2B: data = "Good"      <- safe source, not NULL
        goodB2G: if (data != NULL)  <- null guard exists before access
 
    XPath Checks:
        Check 1: expr_stmt with function call exists at use line
        Check 2: array index access data[0] on pointer confirmed
        Check 3: NO null guard (if data != NULL) before the access
    """
    variable = finding["variable"]
    function = finding["function"]
    used_at  = finding["used_at"]
 
    if not used_at:
        return None
 
    first_use = used_at[0]
    use_line  = extract_line(first_use)
 
    print(f"\n  [char] {variable} in {function}")
    print(f"  {'-' * 40}")
    print(f"  Use location : {first_use}")
    print(f"  Line number  : {use_line}\n")
 
    sink = {
        "variable"            : variable,
        "function"            : function,
        "scenario"            : "char",
        "cwe"                 : "CWE-476",
        "use_line"            : use_line,
        "found_expr_stmt"     : False,
        "found_array_access"  : False,
        "found_no_null_guard" : False,
        "confirmed"           : False
    }
 
    # ── CHECK 1: Find expr_stmt at the use line ──
    # The sink is a statement like: printHexCharLine(data[0])
    xpath1 = (
        f"//src:expr_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    expr_stmts = tree.xpath(xpath1, namespaces=NAMESPACES)
    sink["found_expr_stmt"] = len(expr_stmts) > 0
 
    if sink["found_expr_stmt"]:
        print(f"  [PASS] expr_stmt found at line {use_line}")
    else:
        print(f"  [FAIL] No expr_stmt found at line {use_line}")
        return sink
 
    # ── CHECK 2: Confirm array index access on the variable ──
    # Looks for: data[0] — name followed by index element
    xpath2 = (
        f"//src:expr_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
        f"//src:name[following-sibling::src:index]"
        f"[.='{variable}']"
    )
    array_access = tree.xpath(xpath2, namespaces=NAMESPACES)
    sink["found_array_access"] = len(array_access) > 0
 
    if sink["found_array_access"]:
        print(f"  [PASS] Array access {variable}[0] confirmed")
    else:
        print(f"  [FAIL] No array access found for {variable}")
 
    # ── CHECK 3: Confirm NO null guard before access ──
    # Safe pattern: if (data != NULL) { data[0] }
    # We look for an if_stmt that checks variable != NULL
    # If none exists -> missing null check -> smell confirmed
    xpath3 = (
        f"//src:if_stmt"
        f"//src:name[.='{variable}']"
        f"[following-sibling::src:operator[.='!=']]"
    )
    null_guards = tree.xpath(xpath3, namespaces=NAMESPACES)
    sink["found_no_null_guard"] = len(null_guards) == 0
 
    if sink["found_no_null_guard"]:
        print(f"  [PASS] No null guard found — missing null check confirmed")
    else:
        print(f"  [FAIL] Null guard exists — pointer is safely checked")
 
    # ── ALL 3 CHECKS MUST PASS ──
    sink["confirmed"] = (
        sink["found_expr_stmt"] and
        sink["found_array_access"] and
        sink["found_no_null_guard"]
    )
 
    return sink

# ═════════════════════════════════════════════
# PRINT REPORT
# ═════════════════════════════════════════════

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
        scenario = s.get("scenario", "unknown")
        print(f"\n  [{i}] Variable : {s['variable']}")
        print(f"      Function : {s['function']}")
        print(f"      Scenario : {scenario}")
        print(f"      Use line : {s['use_line']}")
        print(f"      CWE      : {s['cwe']}")
        print(f"\n      XPath Checks:")
        
        if scenario == "binary_if":
            print(f"        {'[PASS]' if s.get('found_if_stmt')     else '[FAIL]'}"
                  f"  if_stmt found at line {s['use_line']}")
            print(f"        {'[PASS]' if s.get('found_bitwise_and') else '[FAIL]'}"
                  f"  operator is '&' (bitwise, not '&&')")
            print(f"        {'[PASS]' if s.get('found_dereference') else '[FAIL]'}"
                  f"  '->' dereference exists")
 
        elif scenario == "char":
            print(f"        {'[PASS]' if s.get('found_expr_stmt')     else '[FAIL]'}"
                  f"  expr_stmt found at line {s['use_line']}")
            print(f"        {'[PASS]' if s.get('found_array_access')  else '[FAIL]'}"
                  f"  array access {s['variable']}[0] confirmed")
            print(f"        {'[PASS]' if s.get('found_no_null_guard') else '[FAIL]'}"
                  f"  no null guard before access")
 
        status = "SINK CONFIRMED ⚠️" if s["confirmed"] else "NOT confirmed"
        print(f"\n      {status}")
 
    print("\n" + "=" * 60 + "\n")


# ═════════════════════════════════════════════
# SAVE REPORT
# ═════════════════════════════════════════════
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
            "scenario"       : s.get("scenario", "unknown"),
            "cwe"            : s["cwe"],
            "use_line"       : s["use_line"],
            "sink_confirmed" : s["confirmed"],
            "xpath_checks"   : {k: v for k, v in s.items()
                                if k.startswith("found_")}
        })

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"  Sink report saved to: {report_file}")
    return report_file