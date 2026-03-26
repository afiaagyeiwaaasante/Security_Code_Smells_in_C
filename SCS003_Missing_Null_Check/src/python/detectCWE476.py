#!/usr/bin/env python3
"""
CWE-476 NULL Pointer Dereference - Detection & Sink Locator
------------------------------------------------------------
Pipeline:
  Step 1: detect_null_pointer_dereference()
          - Reads srcSlice JSON
          - Applies 4 detection rules
          - Outputs findings

  Step 2: locate_sink()
          - Takes findings from Step 1
          - Uses XPath on srcML XML to:
              * Find if_stmt at use line
              * Confirm operator is '&' not '&&'
              * Confirm '->' dereference exists

  Step 3: annotate_xml()
          - Adds sec:smell attribute to confirmed sink
          - Saves annotated XML

Usage:
    python3 detect_cwe476.py <slice.json> <srcml.xml> <output.xml>

Example:
    python3 detect_cwe476.py \
        CWE476_binary_if_01.json \
        CWE476_binary_if_01.xml \
        CWE476_binary_if_01_annotated.xml

Dependencies:
    pip3 install lxml
"""

import json
import sys
import os
from lxml import etree

# ─────────────────────────────────────────────
# NAMESPACES
# ─────────────────────────────────────────────
NAMESPACES = {
    "src" : "http://www.srcML.org/srcML/src",
    "cpp" : "http://www.srcML.org/srcML/cpp",
    "pos" : "http://www.srcML.org/srcML/position",
    "sec" : "security.smells"
}

# ─────────────────────────────────────────────
# KNOWN SINK FUNCTIONS for CWE-476
# ─────────────────────────────────────────────
KNOWN_SINKS = [
    "_bad",
    "bad",
    "deref",
    "use_ptr",
    "access"
]

# ═════════════════════════════════════════════
# STEP 1 — DETECTION RULE
# ═════════════════════════════════════════════
def detect_null_pointer_dereference(slice_profile):
    """
    Applies 4 detection rules to srcSlice JSON.
    Returns list of findings.
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


# ═════════════════════════════════════════════
# STEP 2 — LOCATE SINK WITH XPATH
# ═════════════════════════════════════════════
def extract_line(location):
    """
    Extracts line number from 'filename:line:col' format.
    e.g. 'CWE476.c:25:14' -> '25'
    """
    parts = location.split(":")
    if len(parts) >= 3:
        return parts[-2]
    return location


def locate_sink(tree, finding):
    """
    Uses XPath to locate and confirm the sink in srcML XML.
    Checks:
      1. Find if_stmt at the use line
      2. Confirm operator is '&' (bitwise) not '&&'
      3. Confirm '->' dereference exists
    Returns a sink result dict.
    """
    variable = finding["variable"]
    function = finding["function"]
    used_at  = finding["used_at"]

    if not used_at:
        return None

    # use the first use location to get the line number
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
    xpath1 = (
        f"//src:if_stmt[.//@pos:start"
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
    xpath2 = (
        f"//src:if_stmt[.//@pos:start"
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
    xpath3 = (
        f"//src:if_stmt[.//@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
        f"//src:operator[.='->']"
    )
    deref_ops = tree.xpath(xpath3, namespaces=NAMESPACES)
    sink["found_dereference"] = len(deref_ops) > 0

    if sink["found_dereference"]:
        print(f"  [PASS] Pointer dereference '->' confirmed")
    else:
        print(f"  [FAIL] No '->' dereference found")

    # ── ALL 3 CHECKS MUST PASS ──
    sink["confirmed"] = (
        sink["found_if_stmt"] and
        sink["found_bitwise_and"] and
        sink["found_dereference"]
    )

    return sink


# ═════════════════════════════════════════════
# STEP 3 — ANNOTATE XML
# ═════════════════════════════════════════════
def annotate_xml(tree, sink, output_file):
    """
    Adds sec:smell attribute to the confirmed sink if_stmt node.
    Saves annotated XML to output_file.
    """
    use_line = sink["use_line"]

    xpath = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    nodes = tree.xpath(xpath, namespaces=NAMESPACES)

    if not nodes:
        print(f"  Could not find node to annotate at line {use_line}")
        return

    # annotate the first matching if_stmt
    node = nodes[0]

    #register sec namespace on the root unit element
    root = tree.getroot()
    sec_ns    = "security.smells"
    etree.register_namespace("sec", sec_ns)

    #set the attribute directly on the if_stmt node
    node.set(f"{{{sec_ns}}}smell", "CWE476-null-pointer-dereference-binary-if-high")

    # write annotated XML
    tree.write(
        output_file,
        pretty_print=True,
        xml_declaration=True,
        encoding="UTF-8"
    )
    print(f"\n  Annotated XML saved to: {output_file}")


def save_sink_element(tree, sink, output_file):
    """
    Extracts just the annotated if_stmt element and saves it to a file.
    """
    use_line = sink["use_line"]

    xpath = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    nodes = tree.xpath(xpath, namespaces=NAMESPACES)

    if not nodes:
        print(f"  Could not find sink element at line {use_line}")
        return

    node = nodes[0]

    # serialize just the if_stmt element to string
    sink_xml = etree.tostring(
        node,
        pretty_print=True,
        encoding="unicode"
    )

    # save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(sink_xml)

    print(f"\n  Sink element saved to: {output_file}")
  

# ═════════════════════════════════════════════
# PRINT REPORTS
# ═════════════════════════════════════════════
def print_detection_report(findings, json_file):
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


def print_sink_report(sink_results):
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


def save_sink_report(sink_results, json_file, reports_dir):
    """
    Saves the sink location report as a JSON file
    in the specified reports folder.
    """
    # create reports folder if it doesn't exist
    os.makedirs(reports_dir, exist_ok=True)
 
    # generate report filename from json input filename
    base_name   = os.path.basename(json_file).replace(".json", "_sink_report.json")
    report_file = os.path.join(reports_dir, base_name)
 
    # build report structure
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
 
    # save to file
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
 
    print(f"  Sink report saved to: {report_file}")
    return report_file


# ═════════════════════════════════════════════
# MAIN PIPELINE
# ═════════════════════════════════════════════
def main():
    if len(sys.argv) < 4:
        print("Usage  : python3 detect_cwe476.py <slice.json> <srcml.xml> <output.xml>")
        print("Example: python3 detect_cwe476.py \\")
        print("             CWE476_binary_if_01.json \\")
        print("             CWE476_binary_if_01.xml \\")
        print("             CWE476_binary_if_01_annotated.xml")
        sys.exit(1)

    json_file   = sys.argv[1]
    xml_file    = sys.argv[2]
    output_file = sys.argv[3]

    # validate inputs
    for f in [json_file, xml_file]:
        if not os.path.exists(f):
            print(f"Error: File not found: {f}")
            sys.exit(1)

    # ══════════════════════════════════════
    # STEP 1 — DETECTION
    # ══════════════════════════════════════
    print("\n  Loading slice profile...")
    with open(json_file) as f:
        slice_profile = json.load(f)

    findings = detect_null_pointer_dereference(slice_profile)
    print_detection_report(findings, json_file)

    if not findings:
        print("  No findings to locate. Exiting.\n")
        sys.exit(0)

    # save findings JSON
    findings_file = json_file.replace(".json", "_findings.json")
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"\n  Findings saved to: {findings_file}")

    # ══════════════════════════════════════
    # STEP 2 — LOCATE SINK WITH XPATH
    # ══════════════════════════════════════
    print("\n\n  Loading srcML XML...")
    tree = etree.parse(xml_file)

    sink_results = []
    for finding in findings:
        sink = locate_sink(tree, finding)
        sink_results.append(sink)

    print_sink_report(sink_results)


    # save sink report to SCS003_Missing_Null_Check folder
    save_sink_report(
        sink_results,
        json_file,
        reports_dir="../data/reports/SCS003_Missing_Null_Check"
    )

    # ══════════════════════════════════════
    # STEP 3 — ANNOTATE XML
    # ══════════════════════════════════════
    for sink in sink_results:
        if sink and sink["confirmed"]:
            annotate_xml(tree, sink, output_file)

    print("  Pipeline complete.\n")


    # STEP 4— SINK ELEMENT EXTRACTION
    for sink in sink_results:
        if sink and sink["confirmed"]:
            annotate_xml(tree, sink, output_file)

            # save just the sink element to its own file
            sink_file = output_file.replace(".xml", "_sink_element.xml")
            save_sink_element(tree, sink, sink_file)


if __name__ == "__main__":
    main()