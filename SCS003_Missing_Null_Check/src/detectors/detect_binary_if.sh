#!/usr/bin/env bash
# detectors/detect_binary_if.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: binary_if
# Detects: bitwise & used instead of && in a null-check condition
# Pattern: if((ptr != NULL) & (ptr->field == val))
# Severity: error [nullPointer]
#
# Strategy:
#   srcQL targets the if statement directly — & and && are structurally
#   distinct tokens in srcML so no DIFFERENCE needed. The query matches
#   only if statements using & never &&.
#
#   Multiple matches per file are handled by collecting all -> positions
#   and all variable names as parallel arrays and iterating over them.
#
# Requires: srcml, srcslice, srcattributor, srcql

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1       # annotated srcML XML from pipeline.sh
SRC=$2       # original source file for reading source lines
FINDINGS=$3  # JSON findings file to append to

QUERY='FIND if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {}'

echo "=== Detector 1: binary_if ==="
echo "    query  : $QUERY"
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------I
TMPRESULT=$(mktemp /tmp/srcql_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<if' "$TMPRESULT")" ]; then
    echo "[ binary_if ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract all -> positions — one per matched if statement
# grep requires at least one digit on each side to avoid matching
# the bare colon in pos:start attribute names
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)
{ time {

    ARROW_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="operator"][.="->"]/@*[local-name()="start"]' \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    VARNAMES=$(xmllint --xpath \
        '//*[local-name()="condition"]/*[local-name()="expr"]/*[local-name()="name"][1]' \
        "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

}; } 2>&1
echo

# -----------------------------------------------------------------------
# Build parallel arrays and iterate — one finding per match
# -----------------------------------------------------------------------
echo "--- building findings ---"
{ time {

    ARROW_ARRAY=($ARROW_POSITIONS)
    VARNAME_ARRAY=($VARNAMES)
    COUNT=${#ARROW_ARRAY[@]}

    echo "    matches found: $COUNT"

    for i in $(seq 0 $((COUNT - 1))); do
        ARROW_POS=${ARROW_ARRAY[$i]}
        VARNAME=${VARNAME_ARRAY[$i]}

        ARROW_LINE=$(echo "$ARROW_POS" | cut -d: -f1)
        ARROW_COL=$(echo  "$ARROW_POS" | cut -d: -f2)

        # Declaration position — find decl by variable name
       DECL_POS=$(xmllint --xpath \
            "//*[local-name()='decl'][*[local-name()='name'][.='${VARNAME}']]/@*[local-name()='start']" \
            "$XML" 2>/dev/null \
            | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
            | awk -F: -v arrow="$ARROW_LINE" '$1 < arrow {last=$0} END {print last}')
     
        #Init value - navigate directly into init/expr/name
        DECL_LINE=$(echo "$DECL_POS" | cut -d: -f1)
        DECL_COL=$(echo  "$DECL_POS" | cut -d: -f2)

        # Get init value from the specific decl at DECL_LINE      
        INIT_VAL=$(xmllint --xpath \
            "string(//*[local-name()='decl'][@*[local-name()='start'][starts-with(.,'${DECL_LINE}:')]]/*[local-name()='init']/*[local-name()='expr']/*[local-name()='name'])" \
            "$XML" 2>/dev/null)

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "binary_if" \
            --severity  "error" \
            --classification  "vulnerability" \
            --rule      "nullPointer" \
            --file      "$FILENAME" \
            --line      "$ARROW_LINE" \
            --col       "$ARROW_COL" \
            --varname   "$VARNAME" \
            --note-line "$DECL_LINE" \
            --note-col  "$DECL_COL" \
            --note-msg  "Assignment '${VARNAME}=${INIT_VAL}', assigned value is 0"


        echo "    finding $((i+1)): ${FILENAME}:${ARROW_LINE}:${ARROW_COL} — ${VARNAME}"

    done

}; } 2>&1
echo

echo "[ binary_if ] $COUNT finding(s) written to $FINDINGS"