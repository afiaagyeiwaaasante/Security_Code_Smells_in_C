#!/usr/bin/env bash
# shared/pipeline.sh <source.c> <output.xml> <output.json>
# Shared pipeline — Stages 1-3: srcml -> srcslice -> srcattributor
# Produces an annotated srcML XML file ready for detector queries.
# Requires: srcml, srcslice, srcattributor
set -e

SRC=$1
XML=$2
JSON=$3

echo "=== Stage 1: srcml ==="
{ time srcml "$SRC" --position --hash -o "$XML"; } 2>&1
echo

echo "=== Stage 2: srcslice ==="
{ time srcslice -i "$XML" -o "$JSON"; } 2>&1
echo

echo "=== Stage 3: srcattributor ==="
{ time srcattributor -i "$JSON" -o "$XML"; } 2>&1
echo
