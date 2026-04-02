#!/usr/bin/env bash
# smell_report_multi.sh <source_a.c> <source_b.c> [source_c.c ...]
# Multi-file variant of smell_report.sh
# Combines multiple source files into one srcML archive before running detectors
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

# Use first file's directory for intermediates
DIR=$(dirname "$1")
BASE="combined"
XML="$DIR/$BASE.xml"
JSON="$DIR/$BASE.json"
FINDINGS=$(mktemp /tmp/cwe476_findings_XXXXXX)
trap "rm -f $FINDINGS" EXIT

echo "========================================"
echo " CWE-476 NULL Pointer Dereference Detector"
echo " Mode: multi-file"
echo " Sources: $*"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Stage 1: combine all source files into one srcML archive
# -----------------------------------------------------------------------
echo "=== Stage 1: srcml (combined archive) ==="
{ time srcml "$@" --position --hash -o "$XML"; } 2>&1
echo

# -----------------------------------------------------------------------
# Stage 2: srcslice on the combined archive
# -----------------------------------------------------------------------
echo "=== Stage 2: srcslice ==="
{ time srcslice -i "$XML" -o "$JSON"; } 2>&1
echo

# -----------------------------------------------------------------------
# Stage 3: srcattributor
# -----------------------------------------------------------------------
echo "=== Stage 3: srcattributor ==="
{ time srcattributor -i "$JSON" -o "$XML"; } 2>&1
echo

# Read source lines from all files combined for report output
SRC_LINES=()
for SRC in "$@"; do
    while IFS= read -r line; do
        SRC_LINES+=("$line")
    done < "$SRC"
done

# -----------------------------------------------------------------------
# Run detectors against the combined XML
# Primary source file for reporting is the first argument
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_binary_if.sh"       "$XML" "$1" "$FINDINGS"
echo
bash "$DETECTORS_DIR/detect_interprocedural.sh" "$XML" "$1" "$FINDINGS"
echo
bash "$DETECTORS_DIR/detect_null_deref.sh"      "$XML" "$1" "$FINDINGS"
echo
bash "$DETECTORS_DIR/detect_missing_guard.sh"   "$XML" "$1" "$FINDINGS"
echo

# -----------------------------------------------------------------------
# Final report
# -----------------------------------------------------------------------
bash "$SCRIPT_DIR/report.sh" "$FINDINGS" "$1"