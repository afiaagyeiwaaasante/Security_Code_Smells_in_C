#!/usr/bin/env bash
# smell_report.sh <source.c|cpp> [output_dir]
# CWE-195 Signed-to-Unsigned Conversion Error detector
# All output written to both stdout and an output file for thesis documentation
set -e

SRC=$1

if [ -z "$SRC" ]; then
    echo "Usage: bash smell_report.sh <source.c|cpp> [output_dir]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS_DIR="$SCRIPT_DIR/detectors"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SRC_ABS_DIR=$(cd "$(dirname "$SRC")" && pwd)
CATEGORY=$(basename "$SRC_ABS_DIR")
OUTPUT_DIR=${2:-"$PROJECT_ROOT/results/$CATEGORY"}
mkdir -p "$OUTPUT_DIR"

DIR=$(dirname "$SRC")
BASE=$(basename "$SRC")
XML="$DIR/$BASE.xml"
JSON="$DIR/$BASE.json"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/${BASE%.*}_report_${TIMESTAMP}.txt"
FINDINGS_FILE="${OUTPUT_DIR}/${BASE%.*}_findings_${TIMESTAMP}.json"

FINDINGS=$(mktemp /tmp/cwe195_findings_XXXXXX)

{
    echo "========================================"
    echo " CWE-195 Signed-to-Unsigned Conversion Detector"
    echo " Source  : $SRC"
    echo " Report  : $REPORT_FILE"
    echo " Findings: $FINDINGS_FILE"
    echo " Date    : $(date)"
    echo "========================================"
    echo

    bash "$REPO_ROOT/shared/pipeline.sh" "$SRC" "$XML" "$JSON"

    if [ ! -f "$XML" ]; then
        echo "ERROR: annotated XML not produced — pipeline failed"
        rm -f "$FINDINGS"
        exit 1
    fi

    bash "$DETECTORS_DIR/detect_signed_malloc.sh"  "$XML" "$SRC" "$FINDINGS"
    bash "$DETECTORS_DIR/detect_signed_memcpy.sh"  "$XML" "$SRC" "$FINDINGS"
    bash "$DETECTORS_DIR/detect_signed_strncpy.sh" "$XML" "$SRC" "$FINDINGS"

    cp "$FINDINGS" "$FINDINGS_FILE"
    rm -f "$FINDINGS"

    echo "========================================"
    echo " Findings JSON"
    echo "========================================"
    cat "$FINDINGS_FILE"
    echo

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
