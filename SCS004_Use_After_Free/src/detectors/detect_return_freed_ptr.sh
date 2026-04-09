#!/usr/bin/env bash
# detectors/detect_return_freed_ptr.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 5: return_freed_ptr
# Detects: a function frees a local pointer then returns it, passing a
#           dangling pointer back to the caller
# Severity: error [useAfterFree]
#
# Strategy:
#   srcQL query: FIND $RT $FNAME($PARAMS) {} CONTAINS free($PTR) FOLLOWED BY return $PTR
#   - free($PTR)    matches the deallocation site
#   - FOLLOWED BY   enforces ordering — return must come after free
#   - return $PTR   matches the return statement that escapes the freed pointer
#
#   Position extraction (XPath on srcQL result):
#   - Variable name  : argument of the free() call
#   - Free site      : pos:start of free() call         → note
#   - Return site    : pos:start of first return after free line → finding
#
# Covers: any function returning a freed pointer regardless of type
#
# Does NOT cover:
#   - delete[]/delete variants (C++ — separate query needed)
#   - conditional free paths (flow-sensitive)
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 5: return_freed_ptr ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $RT $FNAME($PARAMS) {} CONTAINS free($PTR) FOLLOWED BY return $PTR'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/rfp_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ return_freed_ptr ] No smell detected."
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

# Free call positions — one per matched free()
FREE_POSITIONS=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="free"]/../@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

# All return statement positions
ALL_RETURN_POSITIONS=$(xmllint --xpath \
    '//*[local-name()="return"]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

# -----------------------------------------------------------------------
# Build findings — for each free, find first return after that line
# -----------------------------------------------------------------------
echo "--- building findings ---"

VARNAME_ARRAY=($VARNAMES)
FREE_ARRAY=($FREE_POSITIONS)
COUNT=${#FREE_ARRAY[@]}

echo "    matches found: $COUNT"

FOUND_COUNT=0

for i in $(seq 0 $((COUNT - 1))); do
    FREE_POS=${FREE_ARRAY[$i]}
    VARNAME=${VARNAME_ARRAY[$i]:-"?"}

    FREE_LINE=$(echo "$FREE_POS" | cut -d: -f1)
    FREE_COL=$(echo  "$FREE_POS" | cut -d: -f2)

    # First return whose start line is > FREE_LINE
    RETURN_POS=$(echo "$ALL_RETURN_POSITIONS" | \
        awk -F: -v fl="$FREE_LINE" '$1 > fl {print; exit}')

    RETURN_LINE=$(echo "$RETURN_POS" | cut -d: -f1)
    RETURN_COL=$(echo  "$RETURN_POS" | cut -d: -f2)

    if [ -z "$RETURN_LINE" ]; then
        echo "    warning: could not determine return site for '${VARNAME}' — skipping"
        continue
    fi

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "return_freed_ptr" \
        --severity  "error" \
        --rule      "useAfterFree" \
        --file      "$FILENAME" \
        --line      "$RETURN_LINE" \
        --col       "$RETURN_COL" \
        --varname   "$VARNAME" \
        --note-line "$FREE_LINE" \
        --note-col  "$FREE_COL" \
        --note-msg  "Memory freed here: free(${VARNAME})"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    finding ${FOUND_COUNT}: ${FILENAME}:${RETURN_LINE}:${RETURN_COL} — ${VARNAME} freed at line ${FREE_LINE}, returned here"
done

echo
echo "[ return_freed_ptr ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
