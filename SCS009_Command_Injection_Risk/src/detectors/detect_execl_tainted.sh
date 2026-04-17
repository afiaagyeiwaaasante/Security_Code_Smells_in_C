#!/usr/bin/env bash
# detect_execl_tainted.sh <xml> <src> <findings>
#
# Detector 3: execl_tainted
# Detects: execl()/execlp() calls where the first argument is NOT a literal
#           and a user-input source (fgets or getenv) is present in the same
#           function — co-occurrence taint model.
# Guard: first argument is a string literal (safe hardcoded path).
# Rule: SCS009-EXECL
#
# Strategy (srcQL + XPath, no Python):
#
#   Stage 1 -- srcQL scopes to the function body:
#     FIND $T $FUNC($PARAMS) {} CONTAINS execl($PATH)
#     (repeated for execlp)
#
#   Stage 1 guard -- XPath on srcQL result:
#     - execl/execlp first arg has no <literal> (non-hardcoded path), AND
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

echo "=== Detector: execl_tainted ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : srcQL + XPath guard -- execl/execlp() with non-literal arg and fgets/getenv present"
echo "    note     : destructor/constructor blocks covered by XPath fallback"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

CALL_XPATH="//*[local-name()='call'][*[local-name()='name'][.='execl' or .='execlp']][*[local-name()='argument_list']/*[local-name()='argument'][1][not(.//*[local-name()='literal'])]]"
TAINT_XPATH="count(//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']])"

found=0

# -----------------------------------------------------------------------
# Stage 1: srcQL -- functions and class methods
# -----------------------------------------------------------------------
for SINK in execl execlp; do
    QUERY="FIND \$T \$FUNC(\$PARAMS) {} CONTAINS ${SINK}(\$PATH)"
    echo "    query : $QUERY"

    TMPRESULT=$(mktemp /tmp/execl_result_XXXXXX)
    trap "rm -f $TMPRESULT" EXIT

    { time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1

    if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
        echo "    no ${SINK}() in regular function"
        rm -f "$TMPRESULT"
        continue
    fi

    echo "--- Stage 1: checking srcQL result for non-literal arg and taint source ---"

    POS=$(xmllint --xpath "string(${CALL_XPATH}/@*[local-name()='start'])" "$TMPRESULT" 2>/dev/null)

    if [ -z "$POS" ]; then
        echo "    guarded -- ${SINK}() first argument is a literal, no finding"
        rm -f "$TMPRESULT"
        continue
    fi

    LINE=${POS%%:*}
    COL=${POS##*:}
    FUNC_NAME=$(xmllint --xpath \
        'string(//*[local-name()="function"]/*[local-name()="name"])' \
        "$TMPRESULT" 2>/dev/null)

    TAINT=$(xmllint --xpath "$TAINT_XPATH" "$TMPRESULT" 2>/dev/null)
    if [ "${TAINT:-0}" -gt 0 ]; then
        SEV="error"; CLASS="vulnerability"
        echo "    taint source present -- escalating to error/vulnerability"
    else
        SEV="warning"; CLASS="smell"
        echo "    no taint source in same function -- warning/smell (possible interprocedural)"
    fi

    echo "    function : $FUNC_NAME"
    echo "    position : $LINE:$COL"
    echo

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "execl_tainted" \
        --severity  "$SEV" \
        --classification  "$CLASS" \
        --rule      "SCS009-EXECL" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${FUNC_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "${SINK}() in ${FUNC_NAME}() -- variable used as exec path; data may contain shell metacharacters"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() ${SINK}() with non-literal path"
    found=$((found + 1))
    rm -f "$TMPRESULT"
done

# -----------------------------------------------------------------------
# Stage 2: XPath fallback -- destructors and constructors
# -----------------------------------------------------------------------
echo
echo "--- Stage 2: XPath destructor/constructor fallback ---"

DES_XPATH="//*[local-name()='call'][*[local-name()='name'][.='execl' or .='execlp']][*[local-name()='argument_list']/*[local-name()='argument'][1][not(.//*[local-name()='literal'])]][ancestor::*[local-name()='destructor' or local-name()='constructor'][.//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']]]]"

DES_POS=$(xmllint --xpath "string(${DES_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -n "$DES_POS" ]; then
    LINE=${DES_POS%%:*}
    COL=${DES_POS##*:}
    FUNC_NAME=$(xmllint --xpath \
        'string(//*[local-name()="destructor" or local-name()="constructor"]/*[local-name()="name"])' \
        "$XML" 2>/dev/null)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "execl_tainted" \
        --severity  "error" \
        --classification  "vulnerability" \
        --rule      "SCS009-EXECL" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${FUNC_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "execl/execlp in ${FUNC_NAME}() -- user input source (fgets/getenv) in same block (destructor/constructor)"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- ${FUNC_NAME}() execl/execlp tainted (destructor/constructor)"
    found=$((found + 1))
else
    echo "    no unguarded destructor/constructor execl/execlp found"
fi

echo
echo "[ execl_tainted ] ${found} finding(s) written to $FINDINGS"
