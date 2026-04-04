#!/usr/bin/env bash
# detectors/detect_interprocedural_uaf.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: interprocedural_uaf (two-pass)
#
# Detects: a pointer is deallocated inside a callee that received it as a parameter;
#           the caller then uses the pointer after the call returns.
#
# Severity:
#   warning [useAfterFree] — callee deallocates its pointer parameter (smell in callee)
#   error   [useAfterFree] — caller uses pointer after calling the unsafe callee
#
# Two-pass strategy:
#
#   Pass 1 — find unsafe callees (three sub-queries, results combined):
#     1a. FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)
#         C malloc/free variants — pointer parameter unconditionally freed.
#     1b. FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete[] $PTR
#         C++ new[]/delete[] variants — array pointer (or reference) parameter deleted.
#     1c. FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete $PTR
#         C++ new/delete variants — scalar pointer (or reference) parameter deleted.
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
# Pass 1 — find unsafe callees: functions that deallocate a pointer parameter
#           Sub-query 1a: free()   Sub-query 1b: delete[]
# -----------------------------------------------------------------------
echo "--- Pass 1: finding unsafe callees ---"

PASS1_FREE_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)'
PASS1_DELETE_ARRAY_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete[] $PTR'
PASS1_DELETE_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete $PTR'

_get_callees() {
    local query="$1"
    srcml "$XML" --srcql "$query" -q \
        | xmllint --xpath \
            '//*[local-name()="function"]/*[local-name()="name"]' \
            - 2>/dev/null \
        | sed 's/<[^>]*>//g' | grep -v '^$' || true
}

{ time {
    CALLEES_FREE=$(        _get_callees "$PASS1_FREE_QUERY")
    CALLEES_DELETE_ARRAY=$(_get_callees "$PASS1_DELETE_ARRAY_QUERY")
    CALLEES_DELETE=$(      _get_callees "$PASS1_DELETE_QUERY")
    UNSAFE_CALLEES=$(printf '%s\n%s\n%s\n' \
        "$CALLEES_FREE" "$CALLEES_DELETE_ARRAY" "$CALLEES_DELETE" \
        | sort -u | grep -v '^$' || true)
}; } 2>&1
echo

echo "    1a (free)    : $(echo "$CALLEES_FREE"         | grep -c . || echo 0) callee(s)"
echo "    1b (delete[]): $(echo "$CALLEES_DELETE_ARRAY" | grep -c . || echo 0) callee(s)"
echo "    1c (delete)  : $(echo "$CALLEES_DELETE"       | grep -c . || echo 0) callee(s)"
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
        --note-msg  "Callee '${CALLEE}' deallocates pointer parameter '${PARAM_NAME}'"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    warning: ${CALLEE_FILE}:${CALLEE_LINE}:${CALLEE_COL} — ${CALLEE} frees parameter ${PARAM_NAME}"

done <<< "$UNSAFE_CALLEES"

echo

# -----------------------------------------------------------------------
# Pass 2 — find callers that use ptr after calling an unsafe callee
#   2a: $CALL($PTR)            bare pointer or dereference (*ptr)
#   2b: $CALL($PTR->$FIELD)    member access (class/struct)
#   2c: $CALL(&$PTR[$IDX])     array-index argument (struct array)
# -----------------------------------------------------------------------
echo "--- Pass 2: finding callers that use ptr after unsafe call ---"

# Helper: run one Pass 2 query variant for a given callee; emit finding if matched.
_run_pass2() {
    local CALLEE="$1"
    local QUERY="$2"
    local TMPRESULT="$3"

    { time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
    echo

    if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
        return 0
    fi

    local CALLER_FILE VARNAME CALLEE_CALL_POS CALLEE_CALL_LINE CALLEE_CALL_COL USE_POS USE_LINE USE_COL

    CALLER_FILE=$(xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

    VARNAME=$(xmllint --xpath \
        "//*[local-name()='call']/*[local-name()='name'][.='${CALLEE}']/../*[local-name()='argument_list']/*[local-name()='argument']//*[local-name()='name']" \
        "$TMPRESULT" 2>/dev/null \
        | sed 's/<[^>]*>//g' | grep -v '^$' | head -1)

    CALLEE_CALL_POS=$(xmllint --xpath \
        "//*[local-name()='call']/*[local-name()='name'][.='${CALLEE}']/../@*[local-name()='start']" \
        "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

    CALLEE_CALL_LINE=$(echo "$CALLEE_CALL_POS" | cut -d: -f1)
    CALLEE_CALL_COL=$(echo  "$CALLEE_CALL_POS" | cut -d: -f2)

    USE_POS=$(xmllint --xpath \
        "//*[local-name()='call'][not(*[local-name()='name'][.='${CALLEE}' or .='free' or .='malloc' or .='calloc' or .='realloc'])]/@*[local-name()='start']" \
        "$TMPRESULT" 2>/dev/null \
        | grep -o '[0-9][0-9]*:[0-9][0-9]*' \
        | awk -F: -v fl="$CALLEE_CALL_LINE" '$1 > fl {print; exit}')

    USE_LINE=$(echo "$USE_POS" | cut -d: -f1)
    USE_COL=$(echo  "$USE_POS" | cut -d: -f2)

    if [ -z "$USE_LINE" ]; then
        echo "    warning: could not determine use site for '${VARNAME}' — skipping"
        return 0
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
}

while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    TMPRESULT=$(mktemp /tmp/uaf_iproc_XXXXXX)
    trap "rm -f $TMPRESULT" RETURN

    echo "  2a [$CALLEE] bare/deref:"
    _run_pass2 "$CALLEE" \
        "FIND \$RT \$CALLER() {} CONTAINS ${CALLEE}(\$PTR) FOLLOWED BY \$CALL(\$PTR)" \
        "$TMPRESULT"

    echo "  2b [$CALLEE] member access:"
    _run_pass2 "$CALLEE" \
        "FIND \$RT \$CALLER() {} CONTAINS ${CALLEE}(\$PTR) FOLLOWED BY \$CALL(\$PTR->\$FIELD)" \
        "$TMPRESULT"

    echo "  2c [$CALLEE] array-index argument:"
    _run_pass2 "$CALLEE" \
        "FIND \$RT \$CALLER() {} CONTAINS ${CALLEE}(\$PTR) FOLLOWED BY \$CALL(&\$PTR[\$IDX])" \
        "$TMPRESULT"

done <<< "$UNSAFE_CALLEES"

echo
echo "[ interprocedural_uaf ] ${FOUND_COUNT} finding(s) written to $FINDINGS"
