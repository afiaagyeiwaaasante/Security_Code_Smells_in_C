#!/usr/bin/env bash
# smell_report.sh <source.c>
#
# Orchestrator — CWE-476 NULL Pointer Dereference detector
# Runs the shared pipeline then each detector in sequence.
# All detectors append findings to a shared JSON file.
# report.sh reads the findings and emits the final report.
#
# Usage:
#   bash smell_report.sh source.c
#
# Detectors run:
#   1. binary_if       — & instead of && in null-check condition
#   2. interprocedural — pointer param dereffed in callee, no guard in caller
#   3. null_deref      — ptr=NULL dereffed with no guard (error)
#   4. missing_guard   — ptr assigned, dereffed with no guard (warning)
#
# Requires: srcml, srcslice, srcattributor, xmllint, python3
set -e

SRC=$1

if [ -z "$SRC" ]; then
    echo "Usage: bash smell_report.sh <source.c>"
    exit 1
fi

# -----------------------------------------------------------------------
# Resolve paths relative to this script's location
# so the script works regardless of where it is called from
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS_DIR="$SCRIPT_DIR/detectors"

# -----------------------------------------------------------------------
# Intermediate files — placed alongside the source file
# -----------------------------------------------------------------------
DIR=$(dirname "$SRC")
BASE=$(basename "$SRC")
XML="$DIR/$BASE.xml"
JSON="$DIR/$BASE.json"

# Findings file — cleared at the start of each run
FINDINGS=$(mktemp /tmp/cwe476_findings_XXXXXX.json)
trap "rm -f $FINDINGS" EXIT

echo "========================================"
echo " CWE-476 NULL Pointer Dereference Detector"
echo " Source: $SRC"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Shared pipeline — runs once, XML used by all detectors
# -----------------------------------------------------------------------
bash "$SCRIPT_DIR/pipeline.sh" "$SRC" "$XML" "$JSON"

# -----------------------------------------------------------------------
# Detector 1: binary_if
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_binary_if.sh" "$XML" "$SRC" "$FINDINGS"
echo

# -----------------------------------------------------------------------
# Detector 2: interprocedural
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_interprocedural.sh" "$XML" "$SRC" "$FINDINGS"
echo

# -----------------------------------------------------------------------
# Detector 3: null_deref (error level)
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_null_deref.sh" "$XML" "$SRC" "$FINDINGS"
echo

# -----------------------------------------------------------------------
# Detector 4: missing_guard (warning level)
# -----------------------------------------------------------------------
bash "$DETECTORS_DIR/detect_missing_guard.sh" "$XML" "$SRC" "$FINDINGS"
echo

# -----------------------------------------------------------------------
# Final report — reads all findings and emits cppcheck-style output
# -----------------------------------------------------------------------
bash "$SCRIPT_DIR/report.sh" "$FINDINGS" "$SRC"