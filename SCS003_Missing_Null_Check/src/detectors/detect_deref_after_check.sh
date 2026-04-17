#!/usr/bin/env bash
# detectors/detect_deref_after_check.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 5: deref_after_check
# Detects: pointer dereferenced inside the body of if(ptr == NULL)
# Pattern: if(ptr == NULL) { ... *ptr ... }
# Severity: error [nullPointer]
#
# Strategy:
#   srcQL targets the if statement directly — matches any if whose condition
#   is ($PTR == NULL) and whose body CONTAINS a dereference of $PTR.
#   The outer wrapper (if(1), while, for, goto, etc.) is irrelevant since
#   the query matches the inner if node regardless of nesting depth.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

QUERY='FIND if($PTR == NULL) {} CONTAINS *$PTR'

echo "=== Detector 5: deref_after_check ==="
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

if [ -z "$(grep '<if' "$TMPRESULT")" ]; then
    echo "[ deref_after_check ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract dereference positions and variable names
# In srcML, *ptr appears as: <operator>*</operator><name>ptr</name>
# We extract the name element's start position (the variable being deref'd)
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

{ time {

    DEREF_POSITIONS=$(xmllint --xpath \
        '//*[local-name()="operator"][.="*"]/following-sibling::*[local-name()="name"][1]/@*[local-name()="start"]' \
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

    DEREF_ARRAY=($DEREF_POSITIONS)
    VARNAME_ARRAY=($VARNAMES)
    COUNT=${#DEREF_ARRAY[@]}

    echo "    matches found: $COUNT"

    for i in $(seq 0 $((COUNT - 1))); do
        DEREF_POS=${DEREF_ARRAY[$i]}
        VARNAME=${VARNAME_ARRAY[$i]:-"?"}

        DEREF_LINE=$(echo "$DEREF_POS" | cut -d: -f1)
        DEREF_COL=$(echo  "$DEREF_POS" | cut -d: -f2)

        # Find the declaration closest above the dereference
        DECL_POS=$(xmllint --xpath \
            "//*[local-name()='decl'][*[local-name()='name'][.='${VARNAME}']]/@*[local-name()='start']" \
            "$XML" 2>/dev/null \
            | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
            | awk -F: -v deref="$DEREF_LINE" '$1 < deref {last=$0} END {print last}')

        DECL_LINE=$(echo "$DECL_POS" | cut -d: -f1)
        DECL_COL=$(echo  "$DECL_POS" | cut -d: -f2)

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "deref_after_check" \
            --severity  "error" \
            --classification  "vulnerability" \
            --rule      "nullPointer" \
            --file      "$FILENAME" \
            --line      "$DEREF_LINE" \
            --col       "$DEREF_COL" \
            --varname   "$VARNAME" \
            --note-line "$DECL_LINE" \
            --note-col  "$DECL_COL" \
            --note-msg  "Assignment '${VARNAME}=NULL', pointer confirmed NULL by if condition"

        echo "    finding $((i+1)): ${FILENAME}:${DEREF_LINE}:${DEREF_COL} — ${VARNAME}"

    done

}; } 2>&1
echo

echo "[ deref_after_check ] $COUNT finding(s) written to $FINDINGS"
