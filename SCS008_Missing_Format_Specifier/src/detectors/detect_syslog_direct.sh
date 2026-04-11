#!/usr/bin/env bash
# detect_syslog_direct.sh <xml> <src> <findings>
#
# Detector 3: syslog_direct
# Detects: syslog calls where the second argument (format) is NOT a string literal
#           AND a user-input source is present in the same function.
# Guard: second <argument> contains a <literal> element (safe format string).
# Rule: SCS008-SYSLOG
#
# Strategy (srcQL + XPath, no Python):
#
#   Stage 1 -- srcQL scopes to the function body:
#     FIND $T $FUNC($PARAMS) {} CONTAINS syslog($PRI)
#
#   Stage 1 guard -- XPath on srcQL result:
#     - syslog second arg has no <literal> (non-hardcoded format), AND
#     - result also contains a taint source call (fgets, getenv, scanf, fscanf).
#
#   Stage 2 -- XPath fallback for <destructor>/<constructor> blocks.
#
#   syslog(priority, format, ...) -- format is the second argument (index 2).
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: syslog_direct ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS syslog($PRI)'
echo "    query    : $QUERY"
echo "    strategy : srcQL + XPath guard -- syslog with non-literal format and taint source present"
echo "    note     : destructor/constructor blocks covered by XPath fallback"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

CALL_XPATH="//*[local-name()='call'][*[local-name()='name'][.='syslog']][*[local-name()='argument_list']/*[local-name()='argument'][2][not(.//*[local-name()='literal'])]]"
TAINT_XPATH="count(//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv' or .='scanf' or .='fscanf']])"

found=0

# -----------------------------------------------------------------------
# Stage 1: srcQL -- functions and class methods
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/syslog_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "    no syslog() in regular function"
else
    echo "--- Stage 1: checking srcQL result for non-literal format and taint source ---"

    POS=$(xmllint --xpath "string(${CALL_XPATH}/@*[local-name()='start'])" "$TMPRESULT" 2>/dev/null)

    if [ -z "$POS" ]; then
        echo "    guarded -- syslog format argument is a literal, no finding"
    else
        TAINT=$(xmllint --xpath "$TAINT_XPATH" "$TMPRESULT" 2>/dev/null)
        if [ "${TAINT:-0}" -eq 0 ]; then
            echo "    no taint source (fgets/getenv/scanf/fscanf) in same function, no finding"
        else
            LINE=${POS%%:*}
            COL=${POS##*:}
            FUNC_NAME=$(xmllint --xpath \
                'string(//*[local-name()="function"]/*[local-name()="name"])' \
                "$TMPRESULT" 2>/dev/null)

            echo "    function : $FUNC_NAME"
            echo "    position : $LINE:$COL"
            echo

            write_finding \
                --findings  "$FINDINGS" \
                --detector  "syslog_direct" \
                --severity  "warning" \
                --rule      "SCS008-SYSLOG" \
                --file      "$FILENAME" \
                --line      "$LINE" \
                --col       "$COL" \
                --varname   "${FUNC_NAME:-?}" \
                --note-line "$LINE" \
                --note-col  "$COL" \
                --note-msg  "syslog in ${FUNC_NAME}() -- variable used directly as format argument (no literal format specifier)"

            echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() syslog without literal format specifier"
            found=$((found + 1))
        fi
    fi
fi

# -----------------------------------------------------------------------
# Stage 2: XPath fallback -- destructors and constructors
# -----------------------------------------------------------------------
echo
echo "--- Stage 2: XPath destructor/constructor fallback ---"

DES_XPATH="//*[local-name()='call'][*[local-name()='name'][.='syslog']][*[local-name()='argument_list']/*[local-name()='argument'][2][not(.//*[local-name()='literal'])]][ancestor::*[local-name()='destructor' or local-name()='constructor'][.//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv' or .='scanf' or .='fscanf']]]]"

DES_POS=$(xmllint --xpath "string(${DES_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -n "$DES_POS" ]; then
    LINE=${DES_POS%%:*}
    COL=${DES_POS##*:}
    FUNC_NAME=$(xmllint --xpath \
        'string(//*[local-name()="destructor" or local-name()="constructor"]/*[local-name()="name"])' \
        "$XML" 2>/dev/null)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "syslog_direct" \
        --severity  "warning" \
        --rule      "SCS008-SYSLOG" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${FUNC_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "syslog in ${FUNC_NAME}() -- variable used directly as format argument (destructor/constructor)"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() syslog without literal format specifier (destructor/constructor)"
    found=$((found + 1))
else
    echo "    no unguarded destructor/constructor syslog found"
fi

echo
echo "[ syslog_direct ] ${found} finding(s) written to $FINDINGS"
