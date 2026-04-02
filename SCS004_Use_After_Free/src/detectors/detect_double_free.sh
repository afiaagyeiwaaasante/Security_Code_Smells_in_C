#!/usr/bin/env bash
# detect_double_free.sh <annotated.xml> <source.c> <findings_file>
# Detector 2 — double_free
# Pattern: free(ptr) followed by free(ptr) in same function without reassignment
# Severity: error / rule: doubleFree
#
# TODO: implement srcQL query and xmllint extraction

XML=$1
SRC=$2
FINDINGS=$3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

echo "=== Detector 2: double_free ==="
echo "(not yet implemented)"
echo
