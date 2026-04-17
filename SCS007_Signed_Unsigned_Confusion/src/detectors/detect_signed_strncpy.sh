#!/usr/bin/env bash
# detectors/detect_signed_strncpy.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: signed_strncpy
# Detects: function passes a signed int to strncpy() as the character count
#           with no positivity guard (data > 0) in any <condition>.
# Severity: warning [signedUnsignedConversion]
#
# Strategy (srcQL + XPath, no Python):
#
#   Stage 1 -- srcQL finds functions and class methods containing:
#     FIND $T $FUNC($PARAMS) {} CONTAINS strncpy($A, $B, $C)
#
#   Stage 1 guard check -- XPath on srcQL result, scoped to <condition> only:
#     count(//*[local-name()="condition"][.//*[local-name()="operator"][.=">"]])
#     If > 0, a positivity guard is present -- no finding.
#
#   Stage 2 -- XPath fallback for <destructor>/<constructor> blocks.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: signed_strncpy ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS strncpy($A, $B, $C)'

echo "    query  : $QUERY"
echo "    note   : destructor/constructor blocks covered by XPath fallback"
echo

GUARD_XPATH='count(//*[local-name()="condition"][.//*[local-name()="operator"][.=">"]])'

DES_XPATH="//*[local-name()='call'][*[local-name()='name'][.='strncpy']][ancestor::*[local-name()='destructor' or local-name()='constructor'][not(.//*[local-name()='condition'][.//*[local-name()='operator'][.='>']])]]/@*[local-name()='start']"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

found=0

# -----------------------------------------------------------------------
# Stage 1: srcQL -- functions and class methods
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/ss_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "--- Stage 1: checking srcQL result for positivity guard in <condition> ---"
    guard=$(xmllint --xpath "$GUARD_XPATH" "$TMPRESULT" 2>/dev/null)
    if [ "${guard:-0}" -gt 0 ]; then
        echo "    guarded -- > operator found in condition, no finding"
    else
        POS=$(xmllint --xpath \
            'string(//*[local-name()="call"][*[local-name()="name"][.="strncpy"]]/@*[local-name()="start"])' \
            "$TMPRESULT" 2>/dev/null)
        FUNC_NAME=$(xmllint --xpath \
            'string(//*[local-name()="function"]/*[local-name()="name"])' \
            "$TMPRESULT" 2>/dev/null)
        LINE=${POS%%:*}
        COL=${POS##*:}

        TAINT_XPATH="count(//*[local-name()='call'][*[local-name()='name'][.='fscanf' or .='scanf' or .='fgets' or .='getenv']])"
        TAINT=$(xmllint --xpath "$TAINT_XPATH" "$TMPRESULT" 2>/dev/null)
        if [ "${TAINT:-0}" -gt 0 ]; then
            SEV="error"; CLASS="vulnerability"
            echo "    taint source present -- escalating to error/vulnerability"
        else
            SEV="warning"; CLASS="smell"
            echo "    no taint source -- warning/smell"
        fi

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "signed_strncpy" \
            --severity  "$SEV" \
            --classification  "$CLASS" \
            --rule      "signedUnsignedConversion" \
            --file      "$FILENAME" \
            --line      "$LINE" \
            --col       "$COL" \
            --varname   "$FUNC_NAME" \
            --note-line "$LINE" \
            --note-col  "$COL" \
            --note-msg  "strncpy() in ${FUNC_NAME}() -- signed int passed as char count with no positivity guard (data > 0)"
        echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() strncpy without positivity guard"
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

    TAINT_XPATH="count(//*[local-name()='call'][*[local-name()='name'][.='fscanf' or .='scanf' or .='fgets' or .='getenv']])"
    TAINT=$(xmllint --xpath "$TAINT_XPATH" "$XML" 2>/dev/null)
    if [ "${TAINT:-0}" -gt 0 ]; then
        SEV="error"; CLASS="vulnerability"
    else
        SEV="warning"; CLASS="smell"
    fi

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "signed_strncpy" \
        --severity  "$SEV" \
        --classification  "$CLASS" \
        --rule      "signedUnsignedConversion" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "$FUNC_NAME" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "strncpy() in ${FUNC_NAME}() -- signed int as char count with no positivity guard (destructor/constructor)"
    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() strncpy without positivity guard (destructor/constructor)"
    found=$((found + 1))
else
    echo "    no unguarded destructor/constructor strncpy found"
fi

echo
echo "[ signed_strncpy ] ${found} finding(s) written to $FINDINGS"
