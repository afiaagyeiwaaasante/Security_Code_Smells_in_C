#!/usr/bin/env bash
# detectors/detect_buffer_size.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: buffer_size_mismatch
# Detects: malloc() called with a multiplication expression as the size argument
#           e.g. malloc(n * sizeof(int)) — if n is large, n * sizeof(int) can
#           integer-overflow to a small value, causing a buffer smaller than intended.
#
# Severity: warning [bufferSizeMismatch]
#
# Strategy:
#   srcQL query: FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
#   Matches any function containing a malloc call whose argument is a product.
#
#   Position extraction (XPath on srcQL result):
#   - Call site  : pos:start of the malloc() call       → finding
#   - Size arg   : first operand of the multiplication  → varname
#   - Func site  : pos:start of surrounding function    → note
#
# Safe alternative: calloc(n, sizeof(T)) — checks for overflow internally.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: buffer_size_mismatch ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/bs_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ buffer_size_mismatch ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract filename, call site, and surrounding function position
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# malloc() call position
CALL_POS=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="malloc"]/../@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

CALL_LINE=$(echo "$CALL_POS" | cut -d: -f1)
CALL_COL=$(echo  "$CALL_POS" | cut -d: -f2)

# First name in the argument list — the count variable
VARNAME=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="malloc"]/../*[local-name()="argument_list"]/*[local-name()="argument"]//*[local-name()="name"]' \
    "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)

# Surrounding function start — used as note location
FUNC_POS=$(xmllint --xpath \
    '//*[local-name()="function"]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

FUNC_LINE=$(echo "$FUNC_POS" | cut -d: -f1)
FUNC_COL=$(echo  "$FUNC_POS" | cut -d: -f2)

if [ -z "$CALL_LINE" ]; then
    echo "    warning: could not determine call site — skipping"
    echo "[ buffer_size_mismatch ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Guard filter: suppress if a SIZE_MAX overflow check precedes the malloc call
# -----------------------------------------------------------------------
echo "--- checking for SIZE_MAX guard ---"

GUARDED=$(python3 << PYEOF
import sys

call_ln = int("$CALL_LINE")

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
    echo "    SIZE_MAX guard found before line $CALL_LINE — suppressing finding (not a smell)"
    echo "[ buffer_size_mismatch ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Emit finding
# -----------------------------------------------------------------------
echo "--- building findings ---"

write_finding \
    --findings  "$FINDINGS" \
    --detector  "buffer_size_mismatch" \
    --severity  "warning" \
    --rule      "bufferSizeMismatch" \
    --file      "$FILENAME" \
    --line      "$CALL_LINE" \
    --col       "$CALL_COL" \
    --varname   "${VARNAME:-n}" \
    --note-line "${FUNC_LINE:-1}" \
    --note-col  "${FUNC_COL:-1}" \
    --note-msg  "malloc(${VARNAME} * sizeof(...)) may overflow — use calloc(${VARNAME}, sizeof(...)) instead"

echo "    finding 1: ${FILENAME}:${CALL_LINE}:${CALL_COL} — malloc(${VARNAME} * ...)"
echo
echo "[ buffer_size_mismatch ] 1 finding(s) written to $FINDINGS"
