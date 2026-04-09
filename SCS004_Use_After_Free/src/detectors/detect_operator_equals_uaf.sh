#!/usr/bin/env bash
# detectors/detect_operator_equals_uaf.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 7: operator_equals_uaf
# Detects: copy assignment operator (operator=) that performs delete[] on a
#           member field without a self-assignment guard (if this != &rhs).
#           When obj = obj is called, this->field and rhs.field alias the same
#           memory: delete[] frees it, then the subsequent read of rhs.field
#           is a use-after-free.
# Severity: error [useAfterFree]
#
# Strategy:
#   srcQL query: FIND $RT operator=($PARAMS) {} CONTAINS delete[] $FIELD
#   Finds all operator= methods that contain a delete[] on a member field.
#
#   Guard detection (XPath on srcQL result):
#   If the result contains an <if> whose condition has both:
#     <name>this</name>  and  <operator>!=</operator>
#   then a self-assignment guard is present → skip (not a flaw).
#   If no such guard → emit finding at the delete[] site.
#
#   Position extraction:
#   - Field name  : name node following the delete operator
#   - Delete site : pos:start of the delete operator → finding
#   - Function    : pos:start of operator= → note
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 7: operator_equals_uaf ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $RT operator=($PARAMS) {} CONTAINS delete[] $FIELD'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/opeq_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ operator_equals_uaf ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Check for self-assignment guard
# -----------------------------------------------------------------------
echo "--- checking for self-assignment guard ---"

GUARD=$(xmllint --xpath \
    '//*[local-name()="if"][.//*[local-name()="condition"][.//*[local-name()="name"][.="this"] and .//*[local-name()="operator"][.="!="]]]' \
    "$TMPRESULT" 2>/dev/null)

if [ -n "$GUARD" ]; then
    echo "    guard found (if this != &...) — not a flaw."
    echo "[ operator_equals_uaf ] No smell detected."
    exit 0
fi

echo "    no self-assignment guard — flaw confirmed."
echo

# -----------------------------------------------------------------------
# Extract filename, field name, and positions
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# Field name — name node following the delete operator (e.g. this->name)
FIELDNAME=$(xmllint --xpath \
    '//*[local-name()="operator"][.="delete"]/../*[local-name()="name"]' \
    "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)

# Delete site position — where the UAF occurs on self-assignment
DELETE_POS=$(xmllint --xpath \
    '//*[local-name()="operator"][.="delete"]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

DELETE_LINE=$(echo "$DELETE_POS" | cut -d: -f1)
DELETE_COL=$(echo  "$DELETE_POS" | cut -d: -f2)

# operator= function start — used as note location
FUNC_POS=$(xmllint --xpath \
    '//*[local-name()="function"]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

FUNC_LINE=$(echo "$FUNC_POS" | cut -d: -f1)
FUNC_COL=$(echo  "$FUNC_POS" | cut -d: -f2)

if [ -z "$DELETE_LINE" ]; then
    echo "    warning: could not determine delete site — skipping"
    echo "[ operator_equals_uaf ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Emit finding
# -----------------------------------------------------------------------
echo "--- building findings ---"

write_finding \
    --findings  "$FINDINGS" \
    --detector  "operator_equals_uaf" \
    --severity  "error" \
    --rule      "useAfterFree" \
    --file      "$FILENAME" \
    --line      "$DELETE_LINE" \
    --col       "$DELETE_COL" \
    --varname   "$FIELDNAME" \
    --note-line "$FUNC_LINE" \
    --note-col  "$FUNC_COL" \
    --note-msg  "operator= lacks self-assignment guard (if this != &rhs) — delete[] on line ${DELETE_LINE} is UAF on self-assignment"

echo "    finding 1: ${FILENAME}:${DELETE_LINE}:${DELETE_COL} — ${FIELDNAME} (no self-assignment guard in operator=)"
echo
echo "[ operator_equals_uaf ] 1 finding(s) written to $FINDINGS"
