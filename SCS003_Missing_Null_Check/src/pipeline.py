#!/usr/bin/env python3
"""
pipeline.py — Main Detection Pipeline
---------------------------------------
SCS003: Missing Null Check (CWE-476)

Orchestrates all three steps of the detection pipeline:

    Step 1 (step1_detect.py)
        - Reads srcSlice JSON
        - Applies 4 detection rules
        - Identifies candidate pointer variables

    Step 2 (step2_locate.py)
        - Reads srcML XML
        - Uses XPath to locate and confirm sink
        - Checks: if_stmt, bitwise &, -> dereference

    Step 3 (step3_annotate.py)
        - Annotates confirmed sink in XML
        - Saves annotated XML and sink element

Usage:
    python3 pipeline.py <slice.json> <srcml.xml> <output.xml>

Example:
    python3 pipeline.py \\
        ../data/SliceFile/CWE476_binary_if_01.json \\
        ../data/XMLFile/CWE476_binary_if_01.xml \\
        ../data/AttributeFile/CWE476_binary_if_01_annotated.xml

Output files:
    ../data/AttributeFile/*_annotated.xml          <- full annotated XML
    ../results/binary_if/*_sink_element.xml         <- extracted sink element
    ../reports/SCS003_Missing_Null_Check/*_sink_report.json  <- JSON report
    ../data/SliceFile/*_findings.json               <- intermediate findings

Dependencies:
    pip3 install lxml --break-system-packages
"""

import json
import sys
import os
from lxml import etree

import step1_detect
import step2_locate
import step3_annotate


# ─────────────────────────────────────────────
# OUTPUT DIRECTORIES
# Adjust these paths relative to src/ folder
# ─────────────────────────────────────────────
REPORTS_DIR = "../reports/SCS003_Missing_Null_Check"
RESULTS_DIR = "../results/binary_if"


def main():
    if len(sys.argv) < 4:
        print("Usage  : python3 pipeline.py <slice.json> <srcml.xml> <output.xml>")
        print("Example: python3 pipeline.py \\")
        print("             ../data/SliceFile/CWE476_binary_if_01.json \\")
        print("             ../data/XMLFile/CWE476_binary_if_01.xml \\")
        print("             ../data/AttributeFile/CWE476_binary_if_01_annotated.xml")
        sys.exit(1)

    json_file   = sys.argv[1]
    xml_file    = sys.argv[2]
    output_file = sys.argv[3]

    # validate inputs
    for f in [json_file, xml_file]:
        if not os.path.exists(f):
            print(f"  Error: File not found: {f}")
            sys.exit(1)

    # ══════════════════════════════════════════
    # STEP 1 — DETECTION RULES
    # Reads JSON, applies 4 rules, finds candidates
    # ══════════════════════════════════════════
    print("\n" + "=" * 60)
    print("  STEP 1: Detection Rules")
    print("=" * 60)
    print(f"\n  Loading slice profile: {json_file}")

    with open(json_file) as f:
        slice_profile = json.load(f)

    findings = step1_detect.detect(slice_profile)
    step1_detect.print_report(findings, json_file)

    if not findings:
        print("  No findings. Exiting pipeline.\n")
        sys.exit(0)

    # save intermediate findings JSON
    findings_file = json_file.replace(".json", "_findings.json")
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"\n  Findings saved to: {findings_file}")

    # ══════════════════════════════════════════
    # STEP 2 — SINK LOCATION (XPath)
    # Locates sink in XML using line numbers from Step 1
    # ══════════════════════════════════════════
    print("\n" + "=" * 60)
    print("  STEP 2: XPath Sink Location")
    print("=" * 60)
    print(f"\n  Loading srcML XML: {xml_file}")

    tree = etree.parse(xml_file)

    sink_results = []
    for finding in findings:
        sink = step2_locate.locate(tree, finding)
        sink_results.append(sink)

    step2_locate.print_report(sink_results)

    # save sink report to reports folder
    step2_locate.save_report(sink_results, json_file, REPORTS_DIR)

    # ══════════════════════════════════════════
    # STEP 3 — XML ANNOTATION
    # Annotates confirmed sinks and saves outputs
    # ══════════════════════════════════════════
    print("\n" + "=" * 60)
    print("  STEP 3: XML Annotation")
    print("=" * 60)

    for sink in sink_results:
        if sink and sink["confirmed"]:
            # annotate full XML
            step3_annotate.annotate(tree, sink, output_file)

            # save sink element to results folder
            step3_annotate.save_sink_element(
                tree, sink, RESULTS_DIR, json_file
            )

    print("\n" + "=" * 60)
    print("  Pipeline complete.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()