#!/usr/bin/env bash
# detectors/detect_no_free_on_exit.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: no_free_on_exit
# Detects: function allocates with malloc() but never calls free() before
#           returning — the allocated block is permanently leaked.
# Severity: warning [memoryLeak]
#
# Strategy:
#   srcQL DIFFERENCE query:
#     FIND $T $FUNC() {} CONTAINS malloc($SIZE)
#     DIFFERENCE
#     FIND $T $FUNC() {} CONTAINS free($PTR)
#
#   Returns only functions that contain malloc() but do NOT contain free() —
#   no Python post-filter needed.
#
#   XPath extraction (on the srcQL result XML):
#     filename  : string(//*[local-name()="unit"]/@filename)
#     call site : //*[local-name()="call"][...name="malloc"...]/@*[local-name()="start"]
#     varname   : //*[local-name()="decl"][...name="malloc"...]/*[local-name()="name"]
#     funcname  : //*[local-name()="function"]/*[local-name()="name"]
#
# Known limitation: path-sensitive leaks (free on one branch only, e.g. early
#   return without free) are not detected — the presence of any free() in the
#   function body causes DIFFERENCE to exclude it. This matches the previous
#   Python detector's behaviour and is documented as a known false negative.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: no_free_on_exit ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC() {} CONTAINS malloc($SIZE) DIFFERENCE FIND $T $FUNC() {} CONTAINS free($PTR)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL DIFFERENCE query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/nofree_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "[ no_free_on_exit ] No smell detected."
    exit 0
fi

echo "--- extracting finding via XPath ---"

# -----------------------------------------------------------------------
# Extract all values via XPath — no Python required
# -----------------------------------------------------------------------
FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' \
    "$TMPRESULT" 2>/dev/null)

POS=$(xmllint --xpath \
    'string(//*[local-name()="call"][*[local-name()="name"][.="malloc"]]/@*[local-name()="start"])' \
    "$TMPRESULT" 2>/dev/null)

VARNAME=$(xmllint --xpath \
    'string(//*[local-name()="decl"][.//*[local-name()="name"][.="malloc"]]/*[local-name()="name"])' \
    "$TMPRESULT" 2>/dev/null)

FUNCNAME=$(xmllint --xpath \
    'string(//*[local-name()="function"]/*[local-name()="name"])' \
    "$TMPRESULT" 2>/dev/null)

# Split "line:col" into separate variables
LINE=${POS%%:*}
COL=${POS##*:}

echo "    function : $FUNCNAME"
echo "    variable : $VARNAME"
echo "    position : $LINE:$COL"
echo

write_finding \
    --findings  "$FINDINGS" \
    --detector  "no_free_on_exit" \
    --severity  "warning" \
    --classification  "smell" \
    --rule      "memoryLeak" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${VARNAME:-$FUNCNAME}" \
    --note-line "$LINE" \
    --note-col  "$COL" \
    --note-msg  "malloc() in ${FUNCNAME}() — no free() on any exit path"

echo "    finding: ${FILENAME}:${LINE}:${COL} — ${VARNAME} (in ${FUNCNAME}(), never freed)"
echo
echo "[ no_free_on_exit ] 1 finding(s) written to $FINDINGS"
