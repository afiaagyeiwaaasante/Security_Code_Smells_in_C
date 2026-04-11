#!/usr/bin/env bash
# detectors/detect_unchecked_add.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: unchecked_add
# Detects: $TYPE $RESULT = $A + $B with no MAX-constant guard in any
#           <condition> element in the same function/destructor/constructor.
# Severity: warning [integerOverflow]
#
# Strategy (srcQL + XPath, no Python):
#
#   Stage 1 -- srcQL finds functions and class methods containing the pattern:
#     FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A + $B
#
#   Stage 1 guard check -- XPath on srcQL result, scoped to <condition> only:
#     count(//*[local-name()="condition"][.//*[local-name()="name"][...MAX...]])
#     If > 0, the addition is guarded -- no finding.
#
#   Stage 2 -- XPath fallback on original XML for <destructor>/<constructor>
#     blocks (same reason as multiply detector).
#
#   Edge case: UINT_MAX as an initialiser value in bad_unsigned_int_add is
#     correctly ignored because the MAX check is scoped to <condition> elements
#     only, not the whole function body. A srcQL DIFFERENCE with CONTAINS
#     UINT_MAX would incorrectly exclude this case.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: unchecked_add ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A + $B'

echo "    query  : $QUERY"
echo "    note   : destructor/constructor blocks covered by XPath fallback"
echo

MAX_IN_COND='count(//*[local-name()="condition"][.//*[local-name()="name"][.="INT_MAX" or .="CHAR_MAX" or .="SHRT_MAX" or .="UINT_MAX" or .="INT64_MAX" or .="LLONG_MAX"]])'

DES_XPATH="//*[local-name()='operator'][.='+'][ancestor::*[local-name()='destructor' or local-name()='constructor'][not(.//*[local-name()='condition'][.//*[local-name()='name'][.='INT_MAX' or .='CHAR_MAX' or .='SHRT_MAX' or .='UINT_MAX' or .='INT64_MAX' or .='LLONG_MAX']])]]/@*[local-name()='start']"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

found=0

# -----------------------------------------------------------------------
# Stage 1: srcQL -- functions and class methods
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/ua_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "--- Stage 1: checking srcQL result for MAX guard in <condition> ---"
    guard=$(xmllint --xpath "$MAX_IN_COND" "$TMPRESULT" 2>/dev/null)
    if [ "${guard:-0}" -gt 0 ]; then
        echo "    guarded -- MAX constant found in condition, no finding"
    else
        POS=$(xmllint --xpath \
            'string(//*[local-name()="operator"][.="+"]/@*[local-name()="start"])' \
            "$TMPRESULT" 2>/dev/null)
        FUNC_NAME=$(xmllint --xpath \
            'string(//*[local-name()="function"]/*[local-name()="name"])' \
            "$TMPRESULT" 2>/dev/null)
        LINE=${POS%%:*}
        COL=${POS##*:}

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "unchecked_add" \
            --severity  "warning" \
            --rule      "integerOverflow" \
            --file      "$FILENAME" \
            --line      "$LINE" \
            --col       "$COL" \
            --varname   "$FUNC_NAME" \
            --note-line "$LINE" \
            --note-col  "$COL" \
            --note-msg  "addition in ${FUNC_NAME}() -- no upper-bound guard before adding"
        echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() adds without MAX guard"
        found=$((found + 1))
    fi
fi

# -----------------------------------------------------------------------
# Stage 2: XPath fallback -- destructors and constructors
# -----------------------------------------------------------------------
echo
echo "--- Stage 2: XPath destructor/constructor fallback ---"
DES_POS=$(xmllint --xpath "string($DES_XPATH)" "$XML" 2>/dev/null)

if [ -n "$DES_POS" ]; then
    LINE=${DES_POS%%:*}
    COL=${DES_POS##*:}
    FUNC_NAME=$(xmllint --xpath \
        'string(//*[local-name()="destructor" or local-name()="constructor"]/*[local-name()="name"])' \
        "$XML" 2>/dev/null)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "unchecked_add" \
        --severity  "warning" \
        --rule      "integerOverflow" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "$FUNC_NAME" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "addition in ${FUNC_NAME}() -- no upper-bound guard before adding"
    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() adds without MAX guard (destructor/constructor)"
    found=$((found + 1))
else
    echo "    no unguarded destructor/constructor addition found"
fi

echo
echo "[ unchecked_add ] ${found} finding(s) written to $FINDINGS"
