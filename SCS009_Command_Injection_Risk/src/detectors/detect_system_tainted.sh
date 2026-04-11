#!/usr/bin/env bash
# detect_system_tainted.sh <xml> <src> <findings>
#
# Detector 1: system_tainted
# Detects: system() calls where the first argument is NOT a literal and a
#           user-input source (fgets or getenv) is present in the same
#           function — co-occurrence taint model.
# Guard: first argument is a string literal (safe hardcoded command).
# Rule: SCS009-SYSTEM
#
# Strategy (srcQL + XPath, no Python):
#
#   Stage 1 -- srcQL scopes to the function body:
#     FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)
#
#   Stage 1 guard -- XPath on srcQL result:
#     - system() first arg has no <literal> (non-hardcoded command), AND
#     - result also contains a fgets or getenv call (taint source present).
#
#   Stage 2 -- XPath fallback for <destructor>/<constructor> blocks
#              (no return type, not matched by srcQL).
#
#   The srcQL result is already scoped to the function body, so the taint
#   source check is a flat count() rather than the ancestor:: predicate
#   needed in pure-XPath mode.
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: system_tainted ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)'
echo "    query    : $QUERY"
echo "    strategy : srcQL + XPath guard -- system() with non-literal arg and fgets/getenv present"
echo "    note     : destructor/constructor blocks covered by XPath fallback"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

CALL_XPATH="//*[local-name()='call'][*[local-name()='name'][.='system']][*[local-name()='argument_list']/*[local-name()='argument'][1][not(.//*[local-name()='literal'])]]"
TAINT_XPATH="count(//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']])"

found=0

# -----------------------------------------------------------------------
# Stage 1: srcQL -- functions and class methods
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/system_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "    no system() in regular function"
else
    echo "--- Stage 1: checking srcQL result for non-literal arg and taint source ---"

    POS=$(xmllint --xpath "string(${CALL_XPATH}/@*[local-name()='start'])" "$TMPRESULT" 2>/dev/null)

    if [ -z "$POS" ]; then
        echo "    guarded -- system() first argument is a literal, no finding"
    else
        TAINT=$(xmllint --xpath "$TAINT_XPATH" "$TMPRESULT" 2>/dev/null)
        if [ "${TAINT:-0}" -eq 0 ]; then
            echo "    no taint source (fgets/getenv) in same function, no finding"
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
                --detector  "system_tainted" \
                --severity  "warning" \
                --rule      "SCS009-SYSTEM" \
                --file      "$FILENAME" \
                --line      "$LINE" \
                --col       "$COL" \
                --varname   "${FUNC_NAME:-?}" \
                --note-line "$LINE" \
                --note-col  "$COL" \
                --note-msg  "system() in ${FUNC_NAME}() -- user input source (fgets/getenv) in same block; data may contain shell metacharacters"

            echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() system() with tainted input"
            found=$((found + 1))
        fi
    fi
fi

# -----------------------------------------------------------------------
# Stage 2: XPath fallback -- destructors and constructors
# -----------------------------------------------------------------------
echo
echo "--- Stage 2: XPath destructor/constructor fallback ---"

DES_XPATH="//*[local-name()='call'][*[local-name()='name'][.='system']][*[local-name()='argument_list']/*[local-name()='argument'][1][not(.//*[local-name()='literal'])]][ancestor::*[local-name()='destructor' or local-name()='constructor'][.//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']]]]"

DES_POS=$(xmllint --xpath "string(${DES_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -n "$DES_POS" ]; then
    LINE=${DES_POS%%:*}
    COL=${DES_POS##*:}
    FUNC_NAME=$(xmllint --xpath \
        'string(//*[local-name()="destructor" or local-name()="constructor"]/*[local-name()="name"])' \
        "$XML" 2>/dev/null)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "system_tainted" \
        --severity  "warning" \
        --rule      "SCS009-SYSTEM" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${FUNC_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "system() in ${FUNC_NAME}() -- user input source (fgets/getenv) in same block (destructor/constructor)"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() system() tainted (destructor/constructor)"
    found=$((found + 1))
else
    echo "    no unguarded destructor/constructor system() found"
fi

echo
echo "[ system_tainted ] ${found} finding(s) written to $FINDINGS"
