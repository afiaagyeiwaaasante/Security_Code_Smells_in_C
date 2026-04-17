#!/usr/bin/env bash
# detectors/detect_missing_guard.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 4: missing_guard — warning level
# Detects: pointer assigned a non-NULL value then dereferenced with no
#           null guard — structurally fragile, not currently exploitable
# Severity: warning [missingNullCheck]
#
# This is a security code smell, not a vulnerability:
#   ptr is valid now but the absence of a null guard means any future
#   change to ptr's source will introduce a crash without warning.
#
# Covers two dereference patterns:
#   struct member access: ptr = &val FOLLOWED BY ptr->field
#   array index access:   ptr = "str" FOLLOWED BY ptr[idx]
#
# Strategy:
#   Find all pointer-assigned-then-dereffed-without-guard functions,
#   then subtract the NULL-assigned case (handled by detect_null_deref)
#   to isolate only the non-NULL assigned smell.
#
# Output:
#   Appends one JSON object per finding to <findings.json>
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 4: missing_guard ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

# Read source lines once
SRC_LINES=()
while IFS= read -r line; do
    SRC_LINES+=("$line")
done < "$SRC"

FOUND_COUNT=0

# -----------------------------------------------------------------------
# Shared run_query function — same structure as detect_null_deref.sh
# -----------------------------------------------------------------------
run_query() {
    local LABEL=$1
    local QUERY=$2
    local DEREF_TOKEN=$3

    echo "--- $LABEL ---"

    local TMPRESULT
    TMPRESULT=$(mktemp /tmp/srcql_result_XXXXXX)
    trap "rm -f $TMPRESULT" RETURN

    { time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
    echo

    FILENAME=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

    if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
        echo "    no findings"
        return
    fi    

    local ARROW_POSITIONS VARNAMES

    if [ "$DEREF_TOKEN" = "->" ]; then
        ARROW_POSITIONS=$(xmllint --xpath \
            '//*[local-name()="operator"][.="->"]/@*[local-name()="start"]' \
            "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

        VARNAMES=$(xmllint --xpath \
            '//*[local-name()="function"]//*[local-name()="decl"]/*[local-name()="name"]' \
            "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' | tail -1)
    else
        ARROW_POSITIONS=$(xmllint --xpath \
            '//*[local-name()="name"][*[local-name()="index"]]/@*[local-name()="start"]' \
            "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

        VARNAMES=$(xmllint --xpath \
            '//*[local-name()="name"][*[local-name()="index"]]/*[local-name()="name"][1]' \
            "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')
    fi

    local ARROW_ARRAY=($ARROW_POSITIONS)
    local VARNAME_ARRAY=($VARNAMES)
    local COUNT=${#ARROW_ARRAY[@]}

    echo "    matches: $COUNT"

    local i
    for i in $(seq 0 $((COUNT - 1))); do
        local ARROW_POS=${ARROW_ARRAY[$i]}
        local VARNAME=${VARNAME_ARRAY[$i]:-"?"}

        local ARROW_LINE=$(echo "$ARROW_POS" | cut -d: -f1)
        local ARROW_COL=$(echo  "$ARROW_POS" | cut -d: -f2)

        # Find assignment closest above the dereference
        # Try slice:def first (separate assignment), then slice:decl (init)
        local DECL_POS
        DECL_POS=$(xmllint --xpath \
            "//*[local-name()='expr'][@*[local-name()='def']]/*[local-name()='name'][.='${VARNAME}']/../@*[local-name()='start']" \
            "$XML" 2>/dev/null \
            | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
            | awk -F: -v arrow="$ARROW_LINE" '$1 < arrow {last=$0} END {print last}')

        if [ -z "$DECL_POS" ]; then
            DECL_POS=$(xmllint --xpath \
                "//*[local-name()='decl'][*[local-name()='name'][.='${VARNAME}']]/@*[local-name()='start']" \
                "$XML" 2>/dev/null \
                | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
                | awk -F: -v arrow="$ARROW_LINE" '$1 < arrow {last=$0} END {print last}')
        fi

        local DECL_LINE=$(echo "$DECL_POS" | cut -d: -f1)
        local DECL_COL=$(echo  "$DECL_POS" | cut -d: -f2)

        local SOURCE_LINE="${SRC_LINES[$((ARROW_LINE - 1))]}"
        local DECL_SOURCE_LINE="${SRC_LINES[$((DECL_LINE - 1))]}"

        local SOURCE_LINE_ESC=$(echo "$SOURCE_LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')
        local DECL_SOURCE_LINE_ESC=$(echo "$DECL_SOURCE_LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "missing_guard" \
            --severity  "warning" \
            --classification  "smell" \
            --rule      "missingNullCheck" \
            --file      "$FILENAME" \
            --line      "$ARROW_LINE" \
            --col       "$ARROW_COL" \
            --varname   "$VARNAME" \
            --note-line "$DECL_LINE" \
            --note-col  "$DECL_COL" \
            --note-msg  "Pointer '${VARNAME}' assigned here without subsequent null guard"
        

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    finding $FOUND_COUNT: ${FILENAME}:${ARROW_LINE}:${ARROW_COL} — ${VARNAME} [$LABEL]"
    done
}

# -----------------------------------------------------------------------
# Query A — struct member smell (ptr = &val, no guard)
# Subtracts NULL-assigned case handled by detect_null_deref
# -----------------------------------------------------------------------
QUERY_STRUCT='FIND $T $FUNC() {} CONTAINS $PT * $PTR = $VAL FOLLOWED BY $PTR->$FIELD WHERE NOT (if($PTR != NULL) {}) DIFFERENCE FIND $T $FUNC() {} CONTAINS $PT * $PTR = NULL FOLLOWED BY $PTR->$FIELD WHERE NOT (if($PTR != NULL) {})'

run_query "struct member (->)" "$QUERY_STRUCT" "->"
echo

# -----------------------------------------------------------------------
# Query B — array index smell (ptr = "str", no guard)
# Subtracts NULL-assigned case handled by detect_null_deref
# -----------------------------------------------------------------------
QUERY_CHAR='FIND $T $FUNC() {} CONTAINS $PTR = $VAL FOLLOWED BY $PTR[$IDX] WHERE NOT (if($PTR != NULL) {}) DIFFERENCE FIND $T $FUNC() {} CONTAINS $PTR = NULL FOLLOWED BY $PTR[$IDX] WHERE NOT (if($PTR != NULL) {})'

run_query "array index ([])" "$QUERY_CHAR" "["
echo

echo "[ missing_guard ] $FOUND_COUNT finding(s) written to $FINDINGS"