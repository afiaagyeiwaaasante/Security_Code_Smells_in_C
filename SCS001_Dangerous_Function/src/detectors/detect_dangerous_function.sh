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

source "$(dirname "$0")/../lib/write_finding.sh"

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
# Extract filename, call site, and surrounding function position
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# gets() call position — where the dangerous call occurs
CALL_POS=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="gets"]/../@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

CALL_LINE=$(echo "$CALL_POS" | cut -d: -f1)
CALL_COL=$(echo  "$CALL_POS" | cut -d: -f2)

# Destination buffer argument passed to gets()
VARNAME=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="gets"]/../*[local-name()="argument_list"]/*[local-name()="argument"]//*[local-name()="name"]' \
    "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)

# Surrounding function start — used as note location
FUNC_POS=$(xmllint --xpath \
    '//*[local-name()="function"]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

FUNC_LINE=$(echo "$FUNC_POS" | cut -d: -f1)
FUNC_COL=$(echo  "$FUNC_POS" | cut -d: -f2)

if [ -z "$CALL_LINE" ]; then
    echo "    warning: could not determine call site — skipping"
    echo "[ dangerous_function ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Emit finding
# -----------------------------------------------------------------------
echo "--- building findings ---"

write_finding \
    --findings  "$FINDINGS" \
    --detector  "dangerous_function" \
    --severity  "error" \
    --rule      "dangerousFunction" \
    --file      "$FILENAME" \
    --line      "$CALL_LINE" \
    --col       "$CALL_COL" \
    --varname   "${VARNAME:-gets}" \
    --note-line "${FUNC_LINE:-1}" \
    --note-col  "${FUNC_COL:-1}" \
    --note-msg  "gets() is inherently dangerous — use fgets(${VARNAME}, size, stdin) instead"

echo "    finding 1: ${FILENAME}:${CALL_LINE}:${CALL_COL} — gets(${VARNAME})"
echo
echo "[ dangerous_function ] 1 finding(s) written to $FINDINGS"
