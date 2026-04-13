#!/usr/bin/env bash
# detectors/detect_dangerous_function.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: dangerous_function
# Detects: calls to inherently dangerous C functions that have no safe variant
#           Currently covers: gets()
#           gets() has no safe usage — always replaced by fgets() with an
#           explicit size limit.
# Severity: error [dangerousFunction]
#
# Strategy:
#   srcQL query: FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
#   Finds any function in the translation unit that contains a call to gets().
#
#   Position extraction (XPath on srcQL result):
#   - Call site     : pos:start of the gets() call             → finding
#   - Function site : pos:start of the surrounding function    → note
#   - Variable name : argument passed to gets() (dest buffer)
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: dangerous_function ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/df_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ dangerous_function ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract filename
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# -----------------------------------------------------------------------
# Extract ALL gets() call positions — one LINE:COL:VARNAME per occurrence
# -----------------------------------------------------------------------
POSITIONS=$(python3 << PYEOF
import re

with open("$TMPRESULT") as f:
    content = f.read()

# Match each gets() call: capture pos:start and the argument variable name
GETS_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>'
    r'\s*<name[^>]*>\s*gets\s*</name>'
    r'.*?<argument\b[^>]*>.*?<name[^>]*>([^<\s]+)</name>',
    re.DOTALL
)

for m in GETS_CALL.finditer(content):
    print(f"{m.group(1)}:{m.group(2)}:{m.group(3).strip()}")
PYEOF
)

if [ -z "$POSITIONS" ]; then
    echo "    warning: could not determine call sites — skipping"
    echo "[ dangerous_function ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Emit one finding per gets() call
# -----------------------------------------------------------------------
echo "--- building findings ---"

COUNT=0
while IFS=: read -r CALL_LINE CALL_COL VARNAME; do
    COUNT=$((COUNT + 1))
    write_finding \
        --findings  "$FINDINGS" \
        --detector  "dangerous_function" \
        --severity  "error" \
        --rule      "dangerousFunction" \
        --file      "$FILENAME" \
        --line      "$CALL_LINE" \
        --col       "$CALL_COL" \
        --varname   "${VARNAME:-gets}" \
        --note-line "$CALL_LINE" \
        --note-col  "$CALL_COL" \
        --note-msg  "gets() is inherently dangerous — use fgets(${VARNAME}, size, stdin) instead"
    echo "    finding $COUNT: ${FILENAME}:${CALL_LINE}:${CALL_COL} — gets(${VARNAME})"
done <<< "$POSITIONS"

echo
echo "[ dangerous_function ] $COUNT finding(s) written to $FINDINGS"
