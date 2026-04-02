#!/usr/bin/env bash
# detectors/detect_use_after_free.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: use_after_free
# Detects: pointer freed with free() then passed as argument to another call
#           in the same function, with no intervening reassignment
# Severity: error [useAfterFree]
#
# Strategy:
#   srcQL query: FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)
#   - free($PTR)      matches the deallocation site
#   - FOLLOWED BY     enforces ordering — $CALL must come after free
#   - $CALL($PTR)     matches any function call where $PTR is an argument
#
#   Position extraction (XPath on srcQL result):
#   - Variable name : argument of the free() call
#   - Free site     : pos:start of the free() call  → note
#   - Use site      : pos:start of the first non-free call after free line → finding
#
# Covers: direct use-after-free via function argument (e.g. printLine(data))
#         char*, int*, struct*, wchar_t* and all malloc/free variants
#
# Does NOT cover (see docs/known_issues.md):
#   - use via array index: free(data); data[0]
#   - use via member access: free(data); data->field
#   - use via pointer dereference: free(data); *data
#   (these need separate queries — see detect_uaf_deref.sh, planned)
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: use_after_free ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/uaf_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ use_after_free ] No smell detected."
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

# All non-free call positions (malloc/calloc/realloc included — filtered later)
ALL_CALL_POSITIONS=$(xmllint --xpath \
    '//*[local-name()="call"][not(*[local-name()="name"][.="free"])]/@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*')

# -----------------------------------------------------------------------
# Build parallel arrays and emit one finding per free/use pair
# -----------------------------------------------------------------------
echo "--- building findings ---"

VARNAME_ARRAY=($VARNAMES)
FREE_ARRAY=($FREE_POSITIONS)
COUNT=${#FREE_ARRAY[@]}

echo "    matches found: $COUNT"

FOUND_COUNT=0

# Read source lines for context
SRC_LINES=()
while IFS= read -r line; do
    SRC_LINES+=("$line")
done < "$SRC"

for i in $(seq 0 $((COUNT - 1))); do
    FREE_POS=${FREE_ARRAY[$i]}
    VARNAME=${VARNAME_ARRAY[$i]:-"?"}

    FREE_LINE=$(echo "$FREE_POS" | cut -d: -f1)
    FREE_COL=$(echo  "$FREE_POS" | cut -d: -f2)

    # First call whose start line is > FREE_LINE — this is the use site
    USE_POS=$(echo "$ALL_CALL_POSITIONS" | \
        awk -F: -v fl="$FREE_LINE" '$1 > fl {print; exit}')

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
echo "[ use_after_free ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
