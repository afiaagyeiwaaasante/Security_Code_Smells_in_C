#!/usr/bin/env python3
"""
preprocess.py — Preprocessing Pipeline
-----------------------------------------
SCS003: Missing Null Check (CWE-476)

Automates the data preparation steps before detection:

    Step A: srcml --position --hash
            Converts C source files to srcML XML

    Step B: srcslice
            Runs srcSlice on XML to generate slice profiles (JSON)

    Step C: srcml --xpath --attribute (optional)
            Adds custom attributes to XML using XPath

Usage:
    # Process a single C file
    python3 preprocess.py --file ../testsuites/binary_if/CWE476_binary_if_01.c

    # Process all C files in a scenario folder
    python3 preprocess.py --scenario binary_if

    # Process all scenarios
    python3 preprocess.py --all

    # Run only specific steps
    python3 preprocess.py --scenario binary_if --steps xml slice

Output:
    ../data/XMLFile/      <- srcML XML files
    ../data/SliceFile/    <- srcSlice JSON files

Dependencies:
    srcml   must be installed and on PATH
    srcslice must be installed and on PATH
"""

import os
import sys
import glob
import argparse
import subprocess


# ─────────────────────────────────────────────
# DIRECTORY PATHS (relative to src/ folder)
# ─────────────────────────────────────────────
TESTSUITES_DIR  = "../testsuites"
XML_DIR         = "../data/XMLFile"
SLICE_DIR       = "../data/SliceFile"
ATTRIBUTE_DIR   = "../data/AttributeFile"

# ─────────────────────────────────────────────
# KNOWN SCENARIOS (Juliet Test Suite variants)
# ─────────────────────────────────────────────
SCENARIOS = [
    "binary_if",
    "char",
    "int",
    "long",
    "struct",
    "twointsstructpointer"
]


# ═════════════════════════════════════════════
# STEP A — srcML: C file → XML
# ═════════════════════════════════════════════
def run_srcml(c_file: str, xml_dir: str) -> str:
    """
    Converts a C source file to srcML XML using:
        srcml --position --hash <input.c> -o <output.xml>

    Args:
        c_file:  path to C source file
        xml_dir: output directory for XML files

    Returns:
        path to generated XML file, or None if failed
    """
    os.makedirs(xml_dir, exist_ok=True)

    # build output filename
    base_name = os.path.basename(c_file).replace(".c", ".xml")
    xml_file  = os.path.join(xml_dir, base_name)

    cmd = [
        "srcml",
        "--position",   # adds pos:start and pos:end to every element
        "--hash",        # adds hash fingerprint to the unit
        c_file,
        "-o", xml_file
    ]

    print(f"\n  [srcML] {os.path.basename(c_file)}")
    print(f"          → {xml_file}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  [ERROR] srcml failed: {result.stderr.strip()}")
            return None

        print(f"  [OK]")
        return xml_file

    except FileNotFoundError:
        print("  [ERROR] srcml not found. Is it installed and on PATH?")
        print("          Run: which srcml")
        return None


# ═════════════════════════════════════════════
# STEP B — srcSlice: XML → JSON
# ═════════════════════════════════════════════
def run_srcslice(xml_file: str, slice_dir: str) -> str:
    """
    Runs srcSlice on a srcML XML file to generate slice profiles:
        srcslice -i <input.xml> -o <output.json>

    Args:
        xml_file:  path to srcML XML file
        slice_dir: output directory for JSON files

    Returns:
        path to generated JSON file, or None if failed
    """
    os.makedirs(slice_dir, exist_ok=True)

    # build output filename
    base_name  = os.path.basename(xml_file).replace(".xml", ".json")
    slice_file = os.path.join(slice_dir, base_name)

    cmd = [
        "srcslice",
        "-i", xml_file,
        "-o", slice_file
    ]

    print(f"\n  [srcSlice] {os.path.basename(xml_file)}")
    print(f"             → {slice_file}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  [ERROR] srcslice failed: {result.stderr.strip()}")
            return None

        print(f"  [OK]")
        return slice_file

    except FileNotFoundError:
        print("  [ERROR] srcslice not found. Is it installed and on PATH?")
        print("          Run: which srcslice")
        return None


# ═════════════════════════════════════════════
# STEP C — srcML XPath Attribute (optional)
# ═════════════════════════════════════════════
def run_srcml_attribute(xml_file: str,
                         xpath: str,
                         namespace_prefix: str,
                         namespace_uri: str,
                         attribute: str,
                         output_file: str) -> str:
    """
    Adds a custom attribute to elements matching an XPath query:
        srcml <input.xml>
            --xmlns:prefix="uri"
            --xpath="..."
            --attribute="prefix:attr=value"
            -o <output.xml>

    Note: srcml --attribute only accepts ONE attribute per call.

    Args:
        xml_file:         input srcML XML file
        xpath:            XPath expression to target elements
        namespace_prefix: namespace prefix (e.g. "sec")
        namespace_uri:    namespace URI (e.g. "security.smells")
        attribute:        attribute string (e.g. "sec:smell=CWE476-high")
        output_file:      output XML file path

    Returns:
        path to output file, or None if failed
    """
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    cmd = [
        "srcml", xml_file,
        f"--xmlns:{namespace_prefix}={namespace_uri}",
        f"--xpath={xpath}",
        f"--attribute={attribute}",
        "-o", output_file
    ]

    print(f"\n  [srcML attr] {os.path.basename(xml_file)}")
    print(f"               xpath     : {xpath}")
    print(f"               attribute : {attribute}")
    print(f"               → {output_file}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  [ERROR] srcml attribute failed: {result.stderr.strip()}")
            return None

        print(f"  [OK]")
        return output_file

    except FileNotFoundError:
        print("  [ERROR] srcml not found.")
        return None


# ═════════════════════════════════════════════
# PROCESS A SINGLE FILE
# ═════════════════════════════════════════════
def process_file(c_file: str, steps: list):
    """
    Runs the full preprocessing pipeline on a single C file.

    Args:
        c_file: path to C source file
        steps:  list of steps to run ["xml", "slice", "attribute"]
    """
    print(f"\n{'=' * 60}")
    print(f"  Processing: {os.path.basename(c_file)}")
    print(f"{'=' * 60}")

    xml_file   = None
    slice_file = None

    # ── STEP A: Generate XML ──
    if "xml" in steps:
        xml_file = run_srcml(c_file, XML_DIR)
        if not xml_file:
            print(f"  Skipping remaining steps for {c_file}")
            return

    # ── STEP B: Generate JSON ──
    if "slice" in steps:
        # find the XML file if we didn't just generate it
        if not xml_file:
            base_name = os.path.basename(c_file).replace(".c", ".xml")
            xml_file  = os.path.join(XML_DIR, base_name)

        if not os.path.exists(xml_file):
            print(f"  [ERROR] XML file not found: {xml_file}")
            print(f"          Run with --steps xml first")
            return

        slice_file = run_srcslice(xml_file, SLICE_DIR)


# ═════════════════════════════════════════════
# PROCESS A SCENARIO FOLDER
# ═════════════════════════════════════════════
def process_scenario(scenario: str, steps: list):
    """
    Processes all C files in a scenario subfolder.

    Args:
        scenario: scenario name (e.g. "binary_if")
        steps:    list of steps to run
    """
    scenario_dir = os.path.join(TESTSUITES_DIR, scenario)

    if not os.path.exists(scenario_dir):
        print(f"  [ERROR] Scenario folder not found: {scenario_dir}")
        return

    c_files = glob.glob(os.path.join(scenario_dir, "*.c"))

    if not c_files:
        print(f"  [ERROR] No .c files found in: {scenario_dir}")
        return

    print(f"\n  Scenario : {scenario}")
    print(f"  Files    : {len(c_files)}")

    for c_file in sorted(c_files):
        process_file(c_file, steps)


# ═════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="SCS003 Preprocessing Pipeline — generates XML and JSON from C files"
    )

    # input options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--file",
        help="Process a single C file",
        metavar="FILE"
    )
    group.add_argument(
        "--scenario",
        help=f"Process all files in a scenario folder. Options: {', '.join(SCENARIOS)}",
        metavar="SCENARIO"
    )
    group.add_argument(
        "--all",
        help="Process all scenarios",
        action="store_true"
    )

    # step options
    parser.add_argument(
        "--steps",
        help="Steps to run (default: xml slice). Options: xml slice attribute",
        nargs="+",
        default=["xml", "slice"],
        choices=["xml", "slice", "attribute"],
        metavar="STEP"
    )

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  SCS003 Preprocessing Pipeline")
    print("=" * 60)
    print(f"  Steps    : {', '.join(args.steps)}")
    print(f"  XML dir  : {XML_DIR}")
    print(f"  Slice dir: {SLICE_DIR}")

    # ── single file ──
    if args.file:
        if not os.path.exists(args.file):
            print(f"\n  [ERROR] File not found: {args.file}")
            sys.exit(1)
        process_file(args.file, args.steps)

    # ── single scenario ──
    elif args.scenario:
        process_scenario(args.scenario, args.steps)

    # ── all scenarios ──
    elif args.all:
        for scenario in SCENARIOS:
            process_scenario(scenario, args.steps)

    print("\n" + "=" * 60)
    print("  Preprocessing complete.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()