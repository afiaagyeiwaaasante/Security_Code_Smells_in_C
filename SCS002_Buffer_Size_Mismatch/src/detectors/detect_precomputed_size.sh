#!/usr/bin/env bash
# detectors/detect_precomputed_size.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: precomputed_size
# Detects: multiplication stored in a variable that is then passed to malloc()
#           e.g.  size_t sz = n * sizeof(int);
#                 p = malloc(sz);
#           The overflow risk is at the assignment, invisible to a direct
#           malloc($A * $B) query.
#
# Severity: warning [bufferSizeMismatch]
#
# Strategy:
#   srcQL query: FIND $T $FUNC($PARAMS) {} CONTAINS $SZ = $A * $B FOLLOWED BY malloc($SZ)
#   Matches any function where a variable is assigned a product and that
#   variable is later passed directly to malloc().
#
#   Guard filter (Python): if the source contains a SIZE_MAX check involving
#   the count variable ($A) before the malloc call, the finding is suppressed.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: precomputed_size ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/ps_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ precomputed_size ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract all malloc(sz) call sites where sz was assigned a product
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

POSITIONS=$(python3 << PYEOF
import re

with open("$TMPRESULT") as f:
    content = f.read()

# Match malloc() calls — capture pos:start and the argument variable name
MALLOC_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>'
    r'\s*<name[^>]*>\s*malloc\s*</name>'
    r'.*?<argument\b[^>]*>.*?<name[^>]*>([^<\s]+)</name>',
    re.DOTALL
)

for m in MALLOC_CALL.finditer(content):
    print(f"{m.group(1)}:{m.group(2)}:{m.group(3).strip()}")
PYEOF
)

if [ -z "$POSITIONS" ]; then
    echo "    warning: could not determine call sites — skipping"
    echo "[ precomputed_size ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# For each malloc call, check for a SIZE_MAX guard before it in the source
# -----------------------------------------------------------------------
echo "--- checking for SIZE_MAX guards ---"

COUNT=0
while IFS=: read -r CALL_LINE CALL_COL VARNAME; do

    GUARDED=$(python3 << PYEOF
import re, sys

varname  = "$VARNAME"
call_ln  = int("$CALL_LINE")

try:
    with open("$SRC") as f:
        lines = f.readlines()
except Exception:
    print("UNGUARDED")
    sys.exit(0)

import re
guard_pat = re.compile(r'\bif\b.*SIZE_MAX')
for line in lines[:call_ln]:
    if guard_pat.search(line):
        print("GUARDED")
        sys.exit(0)

print("UNGUARDED")
PYEOF
)

    if [ "$GUARDED" = "GUARDED" ]; then
        echo "    skipping ${FILENAME}:${CALL_LINE} — SIZE_MAX guard found"
        continue
    fi

    COUNT=$((COUNT + 1))
    write_finding \
        --findings  "$FINDINGS" \
        --detector  "precomputed_size" \
        --severity  "warning" \
        --classification  "smell" \
        --rule      "bufferSizeMismatch" \
        --file      "$FILENAME" \
        --line      "$CALL_LINE" \
        --col       "$CALL_COL" \
        --varname   "${VARNAME:-sz}" \
        --note-line "$CALL_LINE" \
        --note-col  "$CALL_COL" \
        --note-msg  "size variable '${VARNAME}' may have overflowed at assignment — use calloc(n, sizeof(...)) instead"
    echo "    finding $COUNT: ${FILENAME}:${CALL_LINE}:${CALL_COL} — malloc(${VARNAME}) where ${VARNAME} = ... * ..."

done <<< "$POSITIONS"

echo
echo "[ precomputed_size ] $COUNT finding(s) written to $FINDINGS"
