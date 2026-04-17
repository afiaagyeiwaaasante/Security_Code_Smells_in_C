#!/usr/bin/env bash
# detectors/detect_overwrite_leak.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: overwrite_leak
# Detects: pointer is reassigned a new malloc() allocation without first
#           freeing the original allocation — the first block is leaked.
# Severity: warning [overwriteLeak]
#
# Strategy:
#   srcQL DIFFERENCE query:
#     FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B)
#     DIFFERENCE
#     FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY free($PTR) FOLLOWED BY $PTR = malloc($B)
#
#   The base clause matches any function where the same pointer is assigned
#   malloc() twice (declaration then reassignment).
#   The DIFFERENCE clause excludes functions where a free($PTR) appears
#   between the two malloc calls — i.e., the first block was properly freed.
#   $PTR binds consistently across both clauses, ensuring only the same
#   pointer variable triggers the exclusion.
#
#   XPath extraction (on the srcQL result XML):
#     filename      : string(//*[local-name()="unit"]/@filename)
#     first malloc  : (...call...malloc...)[1]/@*[local-name()="start"]  (note position)
#     second malloc : (...call...malloc...)[2]/@*[local-name()="start"]  (finding position)
#     varname       : first <decl> containing malloc -> its <name>
#     funcname      : //*[local-name()="function"]/*[local-name()="name"]
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: overwrite_leak ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B) DIFFERENCE FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY free($PTR) FOLLOWED BY $PTR = malloc($B)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL DIFFERENCE query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/overwrite_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "[ overwrite_leak ] No smell detected."
    exit 0
fi

echo "--- extracting finding via XPath ---"

# -----------------------------------------------------------------------
# Extract all values via XPath -- no Python required
# -----------------------------------------------------------------------
FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' \
    "$TMPRESULT" 2>/dev/null)

# First malloc = original allocation (used in note message)
POS_FIRST=$(xmllint --xpath \
    'string((//*[local-name()="call"][*[local-name()="name"][.="malloc"]])[1]/@*[local-name()="start"])' \
    "$TMPRESULT" 2>/dev/null)

# Second malloc = overwrite site (finding location)
POS_SECOND=$(xmllint --xpath \
    'string((//*[local-name()="call"][*[local-name()="name"][.="malloc"]])[2]/@*[local-name()="start"])' \
    "$TMPRESULT" 2>/dev/null)

VARNAME=$(xmllint --xpath \
    'string(//*[local-name()="decl"][.//*[local-name()="name"][.="malloc"]]/*[local-name()="name"])' \
    "$TMPRESULT" 2>/dev/null)

FUNCNAME=$(xmllint --xpath \
    'string(//*[local-name()="function"]/*[local-name()="name"])' \
    "$TMPRESULT" 2>/dev/null)

# Split "line:col" into separate variables
LINE=${POS_SECOND%%:*}
COL=${POS_SECOND##*:}
FIRST_LINE=${POS_FIRST%%:*}
FIRST_COL=${POS_FIRST##*:}

echo "    function      : $FUNCNAME"
echo "    variable      : $VARNAME"
echo "    first malloc  : $FIRST_LINE:$FIRST_COL"
echo "    overwrite at  : $LINE:$COL"
echo

write_finding \
    --findings  "$FINDINGS" \
    --detector  "overwrite_leak" \
    --severity  "warning" \
    --classification  "smell" \
    --rule      "overwriteLeak" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${VARNAME:-$FUNCNAME}" \
    --note-line "$FIRST_LINE" \
    --note-col  "$FIRST_COL" \
    --note-msg  "Original malloc() of '${VARNAME}' at line ${FIRST_LINE} -- overwritten without free"

echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${VARNAME} overwritten (first alloc at line ${FIRST_LINE})"
echo
echo "[ overwrite_leak ] 1 finding(s) written to $FINDINGS"
