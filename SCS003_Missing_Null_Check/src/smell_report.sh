#!/usr/bin/env bash
# smell_report.sh <source.c> [output_dir]
# CWE-476 NULL Pointer Dereference detector
# All output written to both stdout and an output file for thesis documentation
set -e

SRC=$1

if [ -z "$SRC" ]; then
    echo "Usage: bash smell_report.sh <source.c> [output_dir]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS_DIR="$SCRIPT_DIR/detectors"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Derive output dir from source file's parent directory name (e.g. binary_if, char)
SRC_ABS_DIR=$(cd "$(dirname "$SRC")" && pwd)
CATEGORY=$(basename "$SRC_ABS_DIR")
OUTPUT_DIR=${2:-"$PROJECT_ROOT/results/$CATEGORY"}
mkdir -p "$OUTPUT_DIR"

DIR=$(dirname "$SRC")
BASE=$(basename "$SRC")
XML="$DIR/$BASE.xml"
JSON="$DIR/$BASE.json"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/${BASE%.c}_report_${TIMESTAMP}.txt"
FINDINGS_FILE="${OUTPUT_DIR}/${BASE%.c}_findings_${TIMESTAMP}.json"

# Temp findings file
FINDINGS=$(mktemp /tmp/cwe476_findings_XXXXXX)

# Run everything in a subshell piped to tee
# This works reliably on macOS bash 3.2 and zsh
{
    echo "========================================"
    echo " CWE-476 NULL Pointer Dereference Detector"
    echo " Source  : $SRC"
    echo " Report  : $REPORT_FILE"
    echo " Findings: $FINDINGS_FILE"
    echo " Date    : $(date)"
    echo "========================================"
    echo

    # Pipeline
    bash "$SCRIPT_DIR/pipeline.sh" "$SRC" "$XML" "$JSON"

    if [ ! -f "$XML" ]; then
        echo "ERROR: annotated XML not produced — pipeline failed"
        rm -f "$FINDINGS"
        exit 1
    fi

    # Detectors
    bash "$DETECTORS_DIR/detect_binary_if.sh"       "$XML" "$SRC" "$FINDINGS"
    echo
    bash "$DETECTORS_DIR/detect_interprocedural.sh" "$XML" "$SRC" "$FINDINGS"
    echo
    bash "$DETECTORS_DIR/detect_null_deref.sh"      "$XML" "$SRC" "$FINDINGS"
    echo
    bash "$DETECTORS_DIR/detect_missing_guard.sh"     "$XML" "$SRC" "$FINDINGS"
    echo
    bash "$DETECTORS_DIR/detect_deref_after_check.sh"  "$XML" "$SRC" "$FINDINGS"
    echo
    bash "$DETECTORS_DIR/detect_check_after_deref.sh"  "$XML" "$SRC" "$FINDINGS"
    echo

    # Save findings
    cp "$FINDINGS" "$FINDINGS_FILE"
    rm -f "$FINDINGS"

    # Print findings
    echo "========================================"
    echo " Findings JSON"
    echo "========================================"
    cat "$FINDINGS_FILE"
    echo

    # Summary
    python3 << PYEOF
import json

findings_file = "$FINDINGS_FILE"
content = open(findings_file).read().strip()
findings = []
depth, buf = 0, ""
for ch in content:
    if ch == "{": depth += 1
    if depth > 0: buf += ch
    if ch == "}":
        depth -= 1
        if depth == 0 and buf.strip():
            try: findings.append(json.loads(buf))
            except: pass
            buf = ""

errors   = sum(1 for f in findings if f.get("severity") == "error")
warnings = sum(1 for f in findings if f.get("severity") == "warning")

print("========================================")
print(" Summary")
print(f" Total findings : {len(findings)}")
print(f" Errors         : {errors}")
print(f" Warnings       : {warnings}")
if findings:
    print()
    print(" Breakdown by detector:")
    detectors = {}
    for f in findings:
        d = f.get("detector", "unknown")
        detectors[d] = detectors.get(d, 0) + 1
    for d, count in sorted(detectors.items()):
        print(f"   {d:<25} {count}")
print("========================================")
PYEOF

} 2>&1 | tee "$REPORT_FILE"