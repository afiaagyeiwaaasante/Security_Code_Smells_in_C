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
# Output:
#   Appends one JSON object per finding to <findings.json>
#
# Requires: srcml, xmllint
set -e

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
# -----------------------------------------------------------------------
echo "--- srcQL query ---"
{ time RESULT=$(srcml "$XML" --srcql "$QUERY" -q); } 2>&1
echo

# Check for any matched if statement
if [ -z "$(echo "$RESULT" | grep '<if')" ]; then
    echo "[ binary_if ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract all -> positions — one per matched if statement
# grep requires at least one digit on each side to avoid matching
# the bare colon in pos:start attribute names
# -----------------------------------------------------------------------
echo "--- extracting positions ---"
{ time {

    ARROW_POSITIONS=$(echo "$RESULT" | xmllint --xpath \
        '//*[local-name()="operator"][.="->"]/@*[local-name()="start"]' \
        - 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

    # Extract first name from each condition's direct expr child
    # to get the variable name without duplicates from ptr->field
    VARNAMES=$(echo "$RESULT" | xmllint --xpath \
        '//*[local-name()="condition"]/*[local-name()="expr"]/*[local-name()="name"][1]' \
        - 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')

    FILENAME=$(echo "$RESULT" | xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' - 2>/dev/null)

}; } 2>&1
echo

# -----------------------------------------------------------------------
# Read source lines for report output
# -----------------------------------------------------------------------
SRC_LINES=()
while IFS= read -r line; do
    SRC_LINES+=("$line")
done < "$SRC"

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
     

        DECL_LINE=$(echo "$DECL_POS" | cut -d: -f1)
        DECL_COL=$(echo  "$DECL_POS" | cut -d: -f2)

        # Get init value from the specific decl at DECL_LINE      
        INIT_VAL=$(xmllint --xpath \
            "string(//*[local-name()='decl'][@*[local-name()='start'][starts-with(.,'${DECL_LINE}:')]]/*[local-name()='init']/*[local-name()='expr']/*[local-name()='name'])" \
            "$XML" 2>/dev/null)

        SOURCE_LINE="${SRC_LINES[$((ARROW_LINE - 1))]}"
        DECL_SOURCE_LINE="${SRC_LINES[$((DECL_LINE - 1))]}"

        # Escape strings for JSON
        SOURCE_LINE_ESC=$(echo "$SOURCE_LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')
        DECL_SOURCE_LINE_ESC=$(echo "$DECL_SOURCE_LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')

        # Append finding to JSON file
        cat >> "$FINDINGS" << EOF
{
  "detector": "binary_if",
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
    "message": "Assignment '${VARNAME}=${INIT_VAL}', assigned value is 0"
  }
}
EOF

        echo "    finding $((i+1)): ${FILENAME}:${ARROW_LINE}:${ARROW_COL} — ${VARNAME}"

    done

}; } 2>&1
echo

echo "[ binary_if ] $COUNT finding(s) written to $FINDINGS"