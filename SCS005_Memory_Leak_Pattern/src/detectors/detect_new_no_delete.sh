#!/usr/bin/env bash
# detectors/detect_new_no_delete.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: new_no_delete
# Detects: C++ object allocated with new but delete is never called before
#           the pointer goes out of scope.
# Severity: warning [newNoDelete]
#
# Strategy:
#   srcQL DIFFERENCE query:
#     FIND $T $FUNC() {} CONTAINS new $TYPE()
#     DIFFERENCE
#     FIND $T $FUNC() {} CONTAINS delete $PTR
#
#   Returns only functions that contain new but do NOT contain delete —
#   no Python post-filter needed.
#
#   XPath extraction (on the srcQL result XML):
#     filename  : string(//*[local-name()="unit"]/@filename)
#     call site : //*[local-name()="operator"][.="new"]/@*[local-name()="start"]
#                 (srcML encodes 'new' as <operator>new</operator>)
#     varname   : //*[local-name()="decl"][...operator="new"...]/*[local-name()="name"]
#     funcname  : //*[local-name()="function"]/*[local-name()="name"]
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: new_no_delete ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC() {} CONTAINS new $TYPE() DIFFERENCE FIND $T $FUNC() {} CONTAINS delete $PTR'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL DIFFERENCE query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/newdel_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "[ new_no_delete ] No smell detected."
    exit 0
fi

echo "--- extracting finding via XPath ---"

# -----------------------------------------------------------------------
# Extract all values via XPath -- no Python required
# -----------------------------------------------------------------------
FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' \
    "$TMPRESULT" 2>/dev/null)

POS=$(xmllint --xpath \
    'string(//*[local-name()="operator"][.="new"]/@*[local-name()="start"])' \
    "$TMPRESULT" 2>/dev/null)

VARNAME=$(xmllint --xpath \
    'string(//*[local-name()="decl"][.//*[local-name()="operator"][.="new"]]/*[local-name()="name"])' \
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
    --detector  "new_no_delete" \
    --severity  "warning" \
    --rule      "newNoDelete" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${VARNAME:-$FUNCNAME}" \
    --note-line "$LINE" \
    --note-col  "$COL" \
    --note-msg  "new in ${FUNCNAME}() -- no delete on any exit path"

echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${VARNAME} (in ${FUNCNAME}(), never deleted)"
echo
echo "[ new_no_delete ] 1 finding(s) written to $FINDINGS"
