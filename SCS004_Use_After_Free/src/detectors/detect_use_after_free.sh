#!/usr/bin/env bash
# detectors/detect_use_after_free.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: use_after_free
# Detects: pointer freed with free() then used in the same function,
#           with no intervening reassignment
# Severity: error [useAfterFree]
#
# Two query passes:
#
#   Pass A — bare pointer argument:
#     FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)
#     Covers: char*, int*, int64_t*, long*, wchar_t* malloc/free variants
#     Note: srcQL binds $PTR to the name token — also matches dereferenced
#           use (*data) since `data` appears as a name node in the argument.
#
#   Pass B — array-index argument:
#     FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL(&$PTR[$IDX])
#     Covers: twoIntsStruct* and similar types where use is via &data[0]
#
#   Position extraction (XPath on srcQL result — identical for both passes):
#   - Variable name : argument of the free() call
#   - Free site     : pos:start of the free() call  → note
#   - Use site      : pos:start of the first non-free call after free line → finding
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: use_after_free ==="
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

    # Variable name — argument passed to free()
    local VARNAMES
    VARNAMES=$(xmllint --xpath \
        '//*[local-name()="call"]/*[local-name()="name"][.="free"]/../*[local-name()="argument_list"]/*[local-name()="argument"]//*[local-name()="name"]' \
        "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

    # Free call positions — one per matched free()
    local FREE_POSITIONS
    FREE_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="call"]/*[local-name()="name"][.="free"]/../@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    # All non-free call positions (filtered by line after free)
    local ALL_CALL_POSITIONS
    ALL_CALL_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="call"][not(*[local-name()="name"][.="free" or .="malloc" or .="calloc" or .="realloc"])]/@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    echo "--- building findings ---"

    local VARNAME_ARRAY=($VARNAMES)
    local FREE_ARRAY=($FREE_POSITIONS)
    local COUNT=${#FREE_ARRAY[@]}
    echo "    matches found: $COUNT"

    local i
    for i in $(seq 0 $((COUNT - 1))); do
        local FREE_POS=${FREE_ARRAY[$i]}
        local VARNAME=${VARNAME_ARRAY[$i]:-"?"}

        local FREE_LINE FREE_COL
        FREE_LINE=$(echo "$FREE_POS" | cut -d: -f1)
        FREE_COL=$(echo  "$FREE_POS" | cut -d: -f2)

        # First call whose start line is > FREE_LINE — this is the use site
        local USE_POS
        USE_POS=$(echo "$ALL_CALL_POSITIONS" | \
            awk -F: -v fl="$FREE_LINE" '$1 > fl {print; exit}')

        local USE_LINE USE_COL
        USE_LINE=$(echo "$USE_POS" | cut -d: -f1)
        USE_COL=$(echo  "$USE_POS" | cut -d: -f2)

        if [ -z "$USE_LINE" ]; then
            echo "    warning: could not determine use site for '${VARNAME}' — skipping"
            continue
        fi

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "use_after_free" \
            --severity  "error" \
            --classification  "vulnerability" \
            --rule      "useAfterFree" \
            --file      "$FILENAME" \
            --line      "$USE_LINE" \
            --col       "$USE_COL" \
            --varname   "$VARNAME" \
            --note-line "$FREE_LINE" \
            --note-col  "$FREE_COL" \
            --note-msg  "Memory freed here: free(${VARNAME})"

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    finding ${FOUND_COUNT}: ${FILENAME}:${USE_LINE}:${USE_COL} — ${VARNAME} (freed at line ${FREE_LINE})"
    done
    echo
}

# -----------------------------------------------------------------------
# Run both query passes
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/uaf_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

echo "--- Pass A: bare pointer argument ---"
process_query 'FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)' "$TMPRESULT"

echo "--- Pass B: array-index argument ---"
process_query 'FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL(&$PTR[$IDX])' "$TMPRESULT"

echo "[ use_after_free ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
