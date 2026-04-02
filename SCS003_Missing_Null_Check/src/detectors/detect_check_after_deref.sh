#!/usr/bin/env bash
# detectors/detect_check_after_deref.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 6: check_after_deref
# Detects: null check placed after the pointer has already been dereferenced
# Pattern: *ptr ... if(ptr != NULL) {}
# Severity: warning [missingNullCheck]
#
# Strategy:
#   srcQL uses FOLLOWED BY at the function level to find any function where
#   a dereference of $PTR is followed by if($PTR != NULL). The check is
#   structurally present but comes too late — if the pointer is NULL the
#   dereference will crash before the guard is ever evaluated.
#
#   Outer wrappers (if(1), while, for, goto, etc.) do not affect the query
#   since FOLLOWED BY operates on the function body as a whole.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

QUERY='FIND $T $FUNC() {} CONTAINS *$PTR FOLLOWED BY if($PTR != NULL) {}'

echo "=== Detector 6: check_after_deref ==="
echo "    query  : $QUERY"
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/srcql_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ check_after_deref ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract positions of the if(ptr != NULL) check — that is the misplaced guard
# Variable name comes from the condition of that if statement
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

{ time {

    IF_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="if"]/@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    VARNAMES=$(xmllint --xpath \
        '//*[local-name()="condition"]//*[local-name()="name"][1]' \
        "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

}; } 2>&1
echo

# -----------------------------------------------------------------------
# Build parallel arrays and emit one finding per match
# -----------------------------------------------------------------------
echo "--- building findings ---"
{ time {

    IF_ARRAY=($IF_POSITIONS)
    VARNAME_ARRAY=($VARNAMES)
    COUNT=${#IF_ARRAY[@]}

    echo "    matches found: $COUNT"

    for i in $(seq 0 $((COUNT - 1))); do
        IF_POS=${IF_ARRAY[$i]}
        VARNAME=${VARNAME_ARRAY[$i]:-"?"}

        IF_LINE=$(echo "$IF_POS" | cut -d: -f1)
        IF_COL=$(echo  "$IF_POS" | cut -d: -f2)

        # Find the earliest dereference of this variable above the if
        DEREF_POS=$(xmllint --xpath \
            "//*[local-name()='operator'][.='*']/following-sibling::*[local-name()='name'][.='${VARNAME}']/@*[local-name()='start']" \
            "$XML" 2>/dev/null \
            | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
            | awk -F: -v ifline="$IF_LINE" '$1 < ifline {print; exit}')

        DEREF_LINE=$(echo "$DEREF_POS" | cut -d: -f1)
        DEREF_COL=$(echo  "$DEREF_POS" | cut -d: -f2)

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "check_after_deref" \
            --severity  "warning" \
            --rule      "missingNullCheck" \
            --file      "$FILENAME" \
            --line      "$IF_LINE" \
            --col       "$IF_COL" \
            --varname   "$VARNAME" \
            --note-line "$DEREF_LINE" \
            --note-col  "$DEREF_COL" \
            --note-msg  "Pointer '${VARNAME}' already dereferenced here before null check"

        echo "    finding $((i+1)): ${FILENAME}:${IF_LINE}:${IF_COL} — ${VARNAME}"

    done

}; } 2>&1
echo

echo "[ check_after_deref ] $COUNT finding(s) written to $FINDINGS"
