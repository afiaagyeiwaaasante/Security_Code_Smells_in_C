#!/usr/bin/env bash
# detectors/detect_double_free.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: double_free
# Detects: pointer passed to free() a second time in the same function,
#           with no intervening reassignment
# Severity: error [doubleFree]
#
# Strategy:
#   srcQL query: FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY free($PTR)
#   - free($PTR)     binds $PTR at the first deallocation site
#   - FOLLOWED BY    enforces ordering — second free must come after first
#   - free($PTR)     second call with the same bound $PTR
#
#   Position extraction (XPath on srcQL result):
#   - Variable name  : argument of the first free() call
#   - First free     : pos:start of free() call  → note
#   - Second free    : pos:start of next free() after first free line → finding
#
# Covers: char*, int*, int64_t*, long*, wchar_t*, struct* malloc/free variants
#
# Does NOT cover:
#   - double-free across function calls (interprocedural)
#   - double-free via conditional paths (flow-sensitive)
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: double_free ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY free($PTR)'

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
    echo "[ double_free ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract filename, variable, and positions
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# Variable name — argument passed to free()
VARNAMES=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="free"]/../*[local-name()="argument_list"]/*[local-name()="argument"]//*[local-name()="name"]' \
    "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

# All free() call positions in document order
FREE_POSITIONS=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="free"]/../@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

# -----------------------------------------------------------------------
# Build findings — iterate in pairs: [first_free, second_free]
# -----------------------------------------------------------------------
echo "--- building findings ---"

VARNAME_ARRAY=($VARNAMES)
FREE_ARRAY=($FREE_POSITIONS)
COUNT=${#FREE_ARRAY[@]}

echo "    free() calls found: $COUNT"

FOUND_COUNT=0
PAIR=0

while [ $((PAIR * 2 + 1)) -lt "$COUNT" ]; do
    FIRST_POS=${FREE_ARRAY[$((PAIR * 2))]}
    SECOND_POS=${FREE_ARRAY[$((PAIR * 2 + 1))]}
    VARNAME=${VARNAME_ARRAY[$((PAIR * 2))]:-"?"}

    FIRST_LINE=$(echo "$FIRST_POS"  | cut -d: -f1)
    FIRST_COL=$(echo  "$FIRST_POS"  | cut -d: -f2)
    SECOND_LINE=$(echo "$SECOND_POS" | cut -d: -f1)
    SECOND_COL=$(echo  "$SECOND_POS" | cut -d: -f2)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "double_free" \
        --severity  "error" \
        --classification  "vulnerability" \
        --rule      "doubleFree" \
        --file      "$FILENAME" \
        --line      "$SECOND_LINE" \
        --col       "$SECOND_COL" \
        --varname   "$VARNAME" \
        --note-line "$FIRST_LINE" \
        --note-col  "$FIRST_COL" \
        --note-msg  "Memory first freed here: free(${VARNAME})"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    finding ${FOUND_COUNT}: ${FILENAME}:${SECOND_LINE}:${SECOND_COL} — ${VARNAME} (first freed at line ${FIRST_LINE})"

    PAIR=$((PAIR + 1))
done

echo
echo "[ double_free ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
