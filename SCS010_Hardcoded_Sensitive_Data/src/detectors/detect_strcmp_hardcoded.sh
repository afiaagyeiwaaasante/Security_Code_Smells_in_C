#!/usr/bin/env bash
# detect_strcmp_hardcoded.sh <xml> <src> <findings>
#
# Detector: strcmp_hardcoded
# Detects strcmp()/strncmp() calls where any argument is a string literal,
# indicating a hardcoded password used in an authentication comparison.
# Rule: SCS010-PASSWD-STRCMP
#
# Strategy (XPath only, no srcQL, no Python):
#
#   //*[local-name()='call']
#     [*[local-name()='name'][.='strcmp' or .='strncmp']]
#     [*[local-name()='argument_list']
#       /*[local-name()='argument']
#       [.//*[local-name()='literal'][@type='string']]]
#
#   A finding is emitted when any argument of strcmp/strncmp is a string
#   literal — the literal is the hardcoded credential in the comparison.
#
# Requires: xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: strcmp_hardcoded ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XPath -- strcmp/strncmp with any string literal argument"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

STRCMP_XPATH="//*[local-name()='call'][*[local-name()='name'][.='strcmp' or .='strncmp']][*[local-name()='argument_list']/*[local-name()='argument'][.//*[local-name()='literal'][@type='string']]]"

POS=$(xmllint --xpath "string(${STRCMP_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -z "$POS" ]; then
    echo "[ strcmp_hardcoded ] No smell detected."
    exit 0
fi

LINE=${POS%%:*}
COL=${POS##*:}

FUNC_NAME=$(xmllint --xpath \
    "string(${STRCMP_XPATH}/ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][1]/*[local-name()='name'])" \
    "$XML" 2>/dev/null)

echo "    function : $FUNC_NAME"
echo "    position : $LINE:$COL"
echo

write_finding \
    --findings  "$FINDINGS" \
    --detector  "strcmp_hardcoded" \
    --severity  "error" \
    --classification  "vulnerability" \
    --rule      "SCS010-PASSWD-STRCMP" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${FUNC_NAME:-?}" \
    --note-line "$LINE" \
    --note-col  "$COL" \
    --note-msg  "strcmp/strncmp with hardcoded string literal in ${FUNC_NAME}() -- hardcoded credential in comparison"

echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() strcmp/strncmp with hardcoded literal"
echo
echo "[ strcmp_hardcoded ] 1 finding(s) written to $FINDINGS"
