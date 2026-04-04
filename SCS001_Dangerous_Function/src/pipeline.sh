#!/usr/bin/env bash
# pipeline.sh <source.c> <output.xml> <output.json>
# Converts a C source file to a srcML annotated XML archive with position info.
set -e

SRC=$1
XML=$2
JSON=$3

if [ -z "$SRC" ] || [ -z "$XML" ]; then
    echo "Usage: bash pipeline.sh <source.c> <output.xml> <output.json>"
    exit 1
fi

echo "=== Pipeline ==="
echo "    source : $SRC"
echo "    xml    : $XML"
echo

{ time srcml "$SRC" --position --hash -o "$XML"; } 2>&1
echo
echo "    pipeline complete."
echo
