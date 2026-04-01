#!/usr/bin/env bash
# detectors/detect_null_deref.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: null_deref — error level
# Detects: pointer provably assigned NULL locally then dereferenced
#           with no null guard anywhere in the function
# Severity: error [nullPointer]
#
# Covers two dereference patterns:
#   struct member access: ptr = NULL FOLLOWED BY ptr->field
#   array index access:   ptr = NULL FOLLOWED BY ptr[idx]
#
# Strategy:
#   Run two srcQL queries — one per dereference token.
#   Subtract all functions where a null check exists in any form.
#   What remains is ptr=NULL with no guard anywhere.
#
# Output:
#   Appends one JSON object per finding to <findings.json>
#
# Requires: srcml, xmllint
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: null_deref ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

# Shared DIFFERENCE clauses — subtract all known safe null-check patterns
DIFF='DIFFERENCE FIND $T $FUNC() {} CONTAINS if(($PTR != NULL) && ($PTR->$FIELD == $VAL)) {} DIFFERENCE FIND $T $FUNC() {} CONTAINS if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {} DIFFERENCE FIND $T $FUNC() {} CONTAINS if($PTR != NULL) {}'

# Query A — struct member dereference (ptr->field)
# UNION covers both:
#   - declaration with initializer: twoIntsStruct *ptr = NULL; ptr->field
#   - separate assignment:          ptr = NULL; ptr->field
QUERY_STRUCT="FIND \$T \$FUNC() {} CONTAINS \$TYPE * \$PTR = NULL FOLLOWED BY \$PTR->\$FIELD WHERE NOT (if(\$PTR != NULL) {}) \
UNION \
FIND \$T \$FUNC() {} CONTAINS \$PT * \$PTR = NULL FOLLOWED BY \$PTR->\$FIELD WHERE NOT (if(\$PTR != NULL) {}) \
DIFFERENCE FIND \$T \$FUNC() {} CONTAINS if((\$PTR != NULL) && (\$PTR->\$FIELD == \$VAL)) {} \
DIFFERENCE FIND \$T \$FUNC() {} CONTAINS if(\$PTR != NULL) {}"

# Query B — array index dereference (ptr[idx])
# UNION covers both:
#   - declaration with initializer: char *data = NULL; data[0]
#   - separate assignment:          data = NULL; data[0]
QUERY_CHAR="FIND \$T \$FUNC() {} CONTAINS \$TYPE \$PTR = NULL FOLLOWED BY \$PTR[\$IDX] WHERE NOT (if(\$PTR != NULL) {}) \
UNION \
FIND \$T \$FUNC() {} CONTAINS \$PTR = NULL FOLLOWED BY \$PTR[\$IDX] WHERE NOT (if(\$PTR != NULL) {}) \
DIFFERENCE FIND \$T \$FUNC() {} CONTAINS if(\$PTR != NULL) {}"

# Read source lines once
SRC_LINES=()
while IFS= read -r line; do
    SRC_LINES+=("$line")
done < "$SRC"

FOUND_COUNT=0

# -----------------------------------------------------------------------
# Run query and extract findings — shared function
# -----------------------------------------------------------------------
run_query() {
    local LABEL=$1
    local QUERY=$2
    local DEREF_TOKEN=$3

    echo "--- $LABEL ---"

    # Run query and save to temp file to avoid subshell variable scope issues
    local TMPRESULT
    TMPRESULT=$(mktemp /tmp/srcql_result_XXXXXX.xml)
    trap "rm -f $TMPRESULT" RETURN

    { time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
    echo

    if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
        echo "    no findings"
        return
    fi

    FILENAME=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

    if [ "$DEREF_TOKEN" = "->" ]; then
        ARROW_POSITIONS=$(xmllint --xpath \
            '//*[local-name()="operator"][.="->"]/@*[local-name()="start"]' \
            "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

        VARNAMES=$(xmllint --xpath \
            '//*[local-name()="function"]//*[local-name()="decl"][.//*[local-name()="name"][.="NULL"]]/*[local-name()="name"]' \
            "$TMPRESULT" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)
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

        # Find declaration closest above the dereference
        local DECL_POS
        # Try assignment statement first (data = NULL as separate statement)
        # slice:def marks where a variable is assigned a value
        DECL_POS=$(xmllint --xpath \
            "//*[local-name()='expr'][@*[local-name()='def']]/*[local-name()='name'][.='${VARNAME}']/../@*[local-name()='start']" \
            "$XML" 2>/dev/null \
            | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
            | awk -F: -v arrow="$ARROW_LINE" '$1 < arrow {last=$0} END {print last}')

        # Fall back to declaration with initializer (twoIntsStruct *ptr = NULL)
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

        cat >> "$FINDINGS" << EOF
{
  "detector": "null_deref",
  "severity": "error",
  "rule": "nullPointer",
  "file": "${FILENAME}",
  "line": ${ARROW_LINE},
  "col": ${ARROW_COL},
  "source_line": "${SOURCE_LINE_ESC}",
  "varname": "${VARNAME}",
  "note": {
    "line": ${DECL_LINE},
    "col": ${DECL_COL},
    "source_line": "${DECL_SOURCE_LINE_ESC}",
    "message": "Assignment '${VARNAME}=NULL', assigned value is 0"
  }
}
EOF

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    finding $FOUND_COUNT: ${FILENAME}:${ARROW_LINE}:${ARROW_COL} — ${VARNAME} [$LABEL]"
    done
}
# -----------------------------------------------------------------------
# Run both queries
# -----------------------------------------------------------------------
run_query "struct member (->)" "$QUERY_STRUCT" "->"
echo
run_query "array index ([])" "$QUERY_CHAR" "["
echo

echo "[ null_deref ] $FOUND_COUNT finding(s) written to $FINDINGS"