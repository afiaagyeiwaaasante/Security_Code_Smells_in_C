#!/usr/bin/env bash
# detectors/detect_unchecked_increment.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: unchecked_increment
# Detects: data++ or ++data with no MAX-constant guard in any <condition>
#           element in the enclosing function/destructor/constructor.
# Severity: warning [integerOverflow]
#
# Strategy (XPath only, no srcQL, no Python):
#
#   srcQL cannot express standalone ++ expressions (no $TYPE $RESULT = form).
#   XPath navigates the srcML XML directly:
#
#   //*[local-name()="operator"][.="++"]
#     [ancestor::*[local-name()="function" or
#                  local-name()="destructor" or
#                  local-name()="constructor"]
#      [not(.//*[local-name()="condition"]
#             [.//*[local-name()="name"]
#               [.="INT_MAX" or .="CHAR_MAX" or .="SHRT_MAX" or
#                .="UINT_MAX" or .="INT64_MAX" or .="LLONG_MAX"]])]]
#   /@*[local-name()="start"]
#
#   Finds <operator>++</operator> elements whose enclosing
#   function/destructor/constructor has NO condition with a MAX constant.
#   The ancestor:: axis ensures the guard check is scoped to the same block.
#
#   Position and function name are extracted via separate XPath queries on
#   the same XML file.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: unchecked_increment ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XPath on srcML XML -- ancestor-scoped guard check"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

MAX_NAMES=".='INT_MAX' or .='CHAR_MAX' or .='SHRT_MAX' or .='UINT_MAX' or .='INT64_MAX' or .='LLONG_MAX'"

# XPath: find ++ operators in functions/destructors/constructors with no MAX guard in conditions
INC_XPATH="//*[local-name()='operator'][.='++'][ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][not(.//*[local-name()='condition'][.//*[local-name()='name'][$MAX_NAMES]])]]/@*[local-name()='start']"

POS=$(xmllint --xpath "string($INC_XPATH)" "$XML" 2>/dev/null)

if [ -z "$POS" ]; then
    echo "[ unchecked_increment ] No smell detected."
    exit 0
fi

echo "--- extracting finding via XPath ---"

LINE=${POS%%:*}
COL=${POS##*:}

# Get the enclosing function/destructor/constructor name
FUNC_NAME_XPATH="//*[local-name()='operator'][.='++'][ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][not(.//*[local-name()='condition'][.//*[local-name()='name'][$MAX_NAMES]])]]/ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][1]/*[local-name()='name']"

FUNC_NAME=$(xmllint --xpath "string($FUNC_NAME_XPATH)" "$XML" 2>/dev/null)

echo "    function : $FUNC_NAME"
echo "    position : $LINE:$COL"
echo

write_finding \
    --findings  "$FINDINGS" \
    --detector  "unchecked_increment" \
    --severity  "warning" \
    --rule      "integerOverflow" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${FUNC_NAME:-?}" \
    --note-line "$LINE" \
    --note-col  "$COL" \
    --note-msg  "increment (++) in ${FUNC_NAME}() -- no upper-bound guard (INT_MAX check)"

echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() increments without MAX guard"
echo
echo "[ unchecked_increment ] 1 finding(s) written to $FINDINGS"
