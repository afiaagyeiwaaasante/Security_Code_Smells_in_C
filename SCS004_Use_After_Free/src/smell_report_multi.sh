#!/usr/bin/env bash
# smell_report_multi.sh <source_a.c> <source_b.c> [source_c.c ...]
# Multi-file variant of smell_report.sh for CWE-416
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
FINDINGS=$(mktemp /tmp/cwe416_findings_XXXXXX)
trap "rm -f $FINDINGS" EXIT

echo "========================================"
echo " CWE-416 Use After Free Detector"
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

# -----------------------------------------------------------------------
# Run detectors against the combined XML
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_interprocedural_uaf.sh" "$XML" "$1" "$FINDINGS"

# -----------------------------------------------------------------------
# Final report
# -----------------------------------------------------------------------
bash "$SCRIPT_DIR/report.sh" "$FINDINGS" "$1"
