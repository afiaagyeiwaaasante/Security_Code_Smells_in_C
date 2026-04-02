#!/usr/bin/env bash
# detectors/detect_interprocedural_uaf.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: interprocedural_uaf (two-pass)
#
# Detects: a pointer is freed inside a callee that received it as a parameter;
#           the caller then uses the pointer after the call returns.
#
# Severity:
#   warning [useAfterFree] — callee frees its pointer parameter (smell in callee)
#   error   [useAfterFree] — caller uses pointer after calling the unsafe callee
#
# Two-pass strategy:
#
#   Pass 1 — find unsafe callees:
#     FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)
#     A function that takes a pointer parameter and unconditionally frees it.
#     Emits one warning per callee.
#
#   Pass 2 — find callers that use ptr after calling unsafe callee:
#     FIND $RT $CALLER() {} CONTAINS $CALLEE($PTR) FOLLOWED BY $CALL($PTR)
#     The caller passes $PTR to the unsafe callee, then uses $PTR in another call.
#     Emits one error per caller/use-site pair.
#
# Requires: srcml, xmllint
# Note: for multi-file analysis, combine source files into one archive first
#       using smell_report_multi.sh before running detectors.

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: interprocedural_uaf ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

FOUND_COUNT=0

# -----------------------------------------------------------------------
# Pass 1 — find unsafe callees: functions that free a pointer parameter
# -----------------------------------------------------------------------
echo "--- Pass 1: finding unsafe callees ---"

PASS1_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)'

{ time {
    UNSAFE_CALLEES=$(srcml "$XML" \
        --srcql "$PASS1_QUERY" -q \
        | xmllint --xpath \
            '//*[local-name()="function"]/*[local-name()="name"]' \
            - 2>/dev/null \
        | sed 's/<[^>]*>//g' | grep -v '^$' || true)
}; } 2>&1
echo

if [ -z "$UNSAFE_CALLEES" ]; then
    echo "[ interprocedural_uaf ] No unsafe callees found."
    exit 0
fi

echo "    unsafe callees found:"
echo "$UNSAFE_CALLEES" | while IFS= read -r name; do echo "      $name"; done
echo

# -----------------------------------------------------------------------
# Write a warning for each unsafe callee
# -----------------------------------------------------------------------
while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    CALLEE_RESULT=$(srcml "$XML" \
        --srcql "FIND \$RT ${CALLEE}(\$PT * \$PTR) {}" \
        -q 2>/dev/null)

    CALLEE_FILE=$(echo "$CALLEE_RESULT" | xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' - 2>/dev/null)

    CALLEE_POS=$(echo "$CALLEE_RESULT" | xmllint --xpath \
        'string(//*[local-name()="function"]/@*[local-name()="start"])' \
        - 2>/dev/null)

    CALLEE_LINE=$(echo "$CALLEE_POS" | cut -d: -f1)
    CALLEE_COL=$(echo  "$CALLEE_POS" | cut -d: -f2)
    CALLEE_LINE=${CALLEE_LINE:-1}
    CALLEE_COL=${CALLEE_COL:-1}

    # Parameter name — name that is a direct child of decl (not inside type)
    PARAM_NAME=$(echo "$CALLEE_RESULT" | xmllint --xpath \
        'string(//*[local-name()="function"]/*[local-name()="parameter_list"]/*[local-name()="parameter"]/*[local-name()="decl"]/*[local-name()="name"])' \
        - 2>/dev/null)

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "interprocedural_uaf" \
        --severity  "warning" \
        --rule      "useAfterFree" \
        --file      "$CALLEE_FILE" \
        --line      "$CALLEE_LINE" \
        --col       "$CALLEE_COL" \
        --varname   "$PARAM_NAME" \
        --note-line "$CALLEE_LINE" \
        --note-col  "$CALLEE_COL" \
        --note-msg  "Callee '${CALLEE}' frees pointer parameter '${PARAM_NAME}'"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    warning: ${CALLEE_FILE}:${CALLEE_LINE}:${CALLEE_COL} — ${CALLEE} frees parameter ${PARAM_NAME}"

done <<< "$UNSAFE_CALLEES"

echo

# -----------------------------------------------------------------------
# Pass 2 — find callers that use ptr after calling an unsafe callee
# -----------------------------------------------------------------------
echo "--- Pass 2: finding callers that use ptr after unsafe call ---"

while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    PASS2_QUERY="FIND \$RT \$CALLER() {} CONTAINS ${CALLEE}(\$PTR) FOLLOWED BY \$CALL(\$PTR)"

    TMPRESULT=$(mktemp /tmp/uaf_iproc_XXXXXX)
    trap "rm -f $TMPRESULT" RETURN

    { time srcml "$XML" --srcql "$PASS2_QUERY" -q > "$TMPRESULT"; } 2>&1
    echo

    if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
        echo "    no callers found for ${CALLEE}"
        continue
    fi

    CALLER_FILE=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

    # Variable passed to the unsafe callee
    VARNAME=$(xmllint --xpath \
        "//*[local-name()='call']/*[local-name()='name'][.='${CALLEE}']/../*[local-name()='argument_list']/*[local-name()='argument']//*[local-name()='name']" \
        "$TMPRESULT" 2>/dev/null \
        | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)

    # Position of the unsafe callee call — this becomes the note
    CALLEE_CALL_POS=$(xmllint --xpath \
        "//*[local-name()='call']/*[local-name()='name'][.='${CALLEE}']/../@*[local-name()='start']" \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

    CALLEE_CALL_LINE=$(echo "$CALLEE_CALL_POS" | cut -d: -f1)
    CALLEE_CALL_COL=$(echo  "$CALLEE_CALL_POS" | cut -d: -f2)

    # Use site — first call (not the callee call, not allocators) after callee call line
    USE_POS=$(xmllint --xpath \
        "//*[local-name()='call'][not(*[local-name()='name'][.='${CALLEE}' or .='free' or .='malloc' or .='calloc' or .='realloc'])]/@*[local-name()='start']" \
        "$TMPRESULT" 2>/dev/null \
        | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
        | awk -F: -v fl="$CALLEE_CALL_LINE" '$1 > fl {print; exit}')

    USE_LINE=$(echo "$USE_POS" | cut -d: -f1)
    USE_COL=$(echo  "$USE_POS" | cut -d: -f2)

    if [ -z "$USE_LINE" ]; then
        echo "    warning: could not determine use site for '${VARNAME}' — skipping"
        continue
    fi

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "interprocedural_uaf" \
        --severity  "error" \
        --rule      "useAfterFree" \
        --file      "$CALLER_FILE" \
        --line      "$USE_LINE" \
        --col       "$USE_COL" \
        --varname   "$VARNAME" \
        --note-line "$CALLEE_CALL_LINE" \
        --note-col  "$CALLEE_CALL_COL" \
        --note-msg  "Pointer '${VARNAME}' freed inside '${CALLEE}' called here"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    error: ${CALLER_FILE}:${USE_LINE}:${USE_COL} — '${VARNAME}' used after '${CALLEE}' freed it (call at line ${CALLEE_CALL_LINE})"

done <<< "$UNSAFE_CALLEES"

echo
echo "[ interprocedural_uaf ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
