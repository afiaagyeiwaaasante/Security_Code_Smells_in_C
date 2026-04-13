#!/usr/bin/env bash
# smell_report_multi.sh <source_a.c> <source_b.c> [source_c.c ...]
# CWE-680 Buffer Size Mismatch detector — multi-file variant
# Combines multiple source files into one srcML archive before running detectors.
# Use this for interprocedural cases where the tainted size value originates
# in a different file from the malloc() call.
set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: bash smell_report_multi.sh <file_a.c> <file_b.c> [...]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS_DIR="$SCRIPT_DIR/detectors"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Derive output dir from first file's parent directory name
SRC_ABS_DIR=$(cd "$(dirname "$1")" && pwd)
CATEGORY=$(basename "$SRC_ABS_DIR")
OUTPUT_DIR=${OUTPUT_DIR:-"$PROJECT_ROOT/results/$CATEGORY"}
mkdir -p "$OUTPUT_DIR"

DIR=$(dirname "$1")
BASE="combined"
XML="$DIR/$BASE.xml"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/${BASE}_report_${TIMESTAMP}.txt"
FINDINGS_FILE="${OUTPUT_DIR}/${BASE}_findings_${TIMESTAMP}.json"

FINDINGS=$(mktemp /tmp/cwe680_findings_XXXXXX)
trap "rm -f $FINDINGS" EXIT

{
    echo "========================================"
    echo " CWE-680 Buffer Size Mismatch Detector"
    echo " Mode    : multi-file"
    echo " Sources : $*"
    echo " Report  : $REPORT_FILE"
    echo " Findings: $FINDINGS_FILE"
    echo " Date    : $(date)"
    echo "========================================"
    echo

    # -----------------------------------------------------------------------
    # Stage 1: combine all source files into one srcML archive
    # -----------------------------------------------------------------------
    echo "=== Stage 1: srcml (combined archive) ==="
    { time srcml "$@" --position --hash -o "$XML"; } 2>&1
    echo

    if [ ! -f "$XML" ]; then
        echo "ERROR: combined XML not produced"
        exit 1
    fi

    # -----------------------------------------------------------------------
    # Run detectors against the combined XML
    # -----------------------------------------------------------------------
    bash "$DETECTORS_DIR/detect_buffer_size.sh"      "$XML" "$1" "$FINDINGS"
    bash "$DETECTORS_DIR/detect_precomputed_size.sh" "$XML" "$1" "$FINDINGS"

    # Save findings
    cp "$FINDINGS" "$FINDINGS_FILE"

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
