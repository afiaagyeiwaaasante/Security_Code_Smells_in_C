#!/usr/bin/env bash
# detectors/detect_delete_array_uaf.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 4: delete_array_uaf
# Detects: pointer deleted with delete[] then used in the same function,
#           with no intervening reassignment
# Severity: error [useAfterFree]
#
# Two query passes (combined into one detector):
#   Pass A — bare pointer argument:
#     FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL($PTR)
#     Covers: char*, int64_t*, long*, wchar_t* new[]/delete[] variants
#
#   Pass B — struct/array-index argument:
#     FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL(&$PTR[$IDX])
#     Covers: twoIntsStruct* and similar types where use is via &data[0]
#
#   Position extraction (XPath on srcQL result — identical for both passes):
#   - Variable name : name node following the delete operator
#   - Delete site   : pos:start of the delete operator  → note
#   - Use site      : pos:start of the first non-system call after delete line → finding
#
# Does NOT cover:
#   - use via array index only: delete[] data; data[0]
#   - use via member access:    delete[] data; data->field
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 4: delete_array_uaf ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

FOUND_COUNT=0

# -----------------------------------------------------------------------
# process_query <query> <tmpfile>
# Runs one srcQL query, extracts positions, emits findings.
# Accumulates into global FOUND_COUNT.
# -----------------------------------------------------------------------
process_query() {
    local QUERY="$1"
    local TMPRESULT="$2"

    echo "    query  : $QUERY"
    { time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
    echo

    if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
        echo "    no match for this query."
        echo
        return
    fi

    echo "--- extracting positions ---"

    local FILENAME
    FILENAME=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

    # Variable name — name node that follows the delete operator
    local VARNAMES
    VARNAMES=$(xmllint --xpath \
        '//*[local-name()="operator"][.="delete"]/../*[local-name()="name"]' \
        "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

    # Delete operator positions — one per matched delete[]
    local DELETE_POSITIONS
    DELETE_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="operator"][.="delete"]/@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    # All non-system call positions (filtered by line after delete)
    local ALL_CALL_POSITIONS
    ALL_CALL_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="call"][not(*[local-name()="name"][.="memset" or .="memcpy" or .="malloc" or .="calloc" or .="realloc"])]/@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    echo "--- building findings ---"

    local VARNAME_ARRAY=($VARNAMES)
    local DELETE_ARRAY=($DELETE_POSITIONS)
    local COUNT=${#DELETE_ARRAY[@]}
    echo "    matches found: $COUNT"

    local i
    for i in $(seq 0 $((COUNT - 1))); do
        local DELETE_POS=${DELETE_ARRAY[$i]}
        local VARNAME=${VARNAME_ARRAY[$i]:-"?"}

        local DELETE_LINE DELETE_COL
        DELETE_LINE=$(echo "$DELETE_POS" | cut -d: -f1)
        DELETE_COL=$(echo  "$DELETE_POS" | cut -d: -f2)

        # First call whose start line is > DELETE_LINE — this is the use site
        local USE_POS
        USE_POS=$(echo "$ALL_CALL_POSITIONS" | \
            awk -F: -v dl="$DELETE_LINE" '$1 > dl {print; exit}')

        local USE_LINE USE_COL
        USE_LINE=$(echo "$USE_POS" | cut -d: -f1)
        USE_COL=$(echo  "$USE_POS" | cut -d: -f2)

        if [ -z "$USE_LINE" ]; then
            echo "    warning: could not determine use site for '${VARNAME}' — skipping"
            continue
        fi

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "delete_array_uaf" \
            --severity  "error" \
            --rule      "useAfterFree" \
            --file      "$FILENAME" \
            --line      "$USE_LINE" \
            --col       "$USE_COL" \
            --varname   "$VARNAME" \
            --note-line "$DELETE_LINE" \
            --note-col  "$DELETE_COL" \
            --note-msg  "Memory deleted here: delete[] ${VARNAME}"

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    finding ${FOUND_COUNT}: ${FILENAME}:${USE_LINE}:${USE_COL} — ${VARNAME} (deleted at line ${DELETE_LINE})"
    done
    echo
}

# -----------------------------------------------------------------------
# Run both query passes
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/da_uaf_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

echo "--- Pass A: bare pointer argument ---"
process_query 'FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL($PTR)' "$TMPRESULT"

echo "--- Pass B: struct/array-index argument ---"
process_query 'FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL(&$PTR[$IDX])' "$TMPRESULT"

echo "[ delete_array_uaf ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
