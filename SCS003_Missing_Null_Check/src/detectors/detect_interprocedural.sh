#!/usr/bin/env bash
# detectors/detect_interprocedural.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: interprocedural
# Detects: pointer parameter dereferenced in callee with no null check,
#           caller passes pointer without guarding it first
#
# Severity levels:
#   error   [nullPointer]      — callee deref no guard + caller passes NULL provably
#   warning [missingNullCheck] — callee deref no guard + caller passes unguarded ptr
#
# Excluded:
#   callees that contain if($PTR != NULL) anywhere — structurally safe
#
# Covers two dereference patterns:
#   struct member: ptr->field
#   array index:   ptr[idx]
#
# Strategy:
#   Pass 1 — find unsafe callees: dereference without null check
#             UNION covers -> and [] patterns
#             DIFFERENCE excludes callees with any null check
#             Write a callee-level smell warning for each
#
#   Pass 2a — error: for each callee, find callers that pass NULL
#   Pass 2b — warning: for each callee, find callers that pass any
#              unguarded pointer, minus those caught by 2a and
#              minus those that guard before the call
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: interprocedural ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

FOUND_COUNT=0

# -----------------------------------------------------------------------
# Helper: extract call site position from srcQL result
# -----------------------------------------------------------------------
get_call_pos() {
    local RESULT=$1
    local CALLEE=$2
    local POS

    POS=$(echo "$RESULT" | xmllint --xpath \
        "//*[local-name()='call'][*[local-name()='name'][.='${CALLEE}']]/@*[local-name()='start']" \
        - 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

    if [ -z "$POS" ]; then
        POS=$(echo "$RESULT" | xmllint --xpath \
            'string(//*[local-name()="function"]/@*[local-name()="start"])' \
            - 2>/dev/null)
    fi

    echo "${POS:-1:1}"
}

# -----------------------------------------------------------------------
# Pass 1: find unsafe callees
# -----------------------------------------------------------------------
echo "--- Pass 1: finding unsafe callees ---"

PASS1_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR->$FIELD WHERE NOT (if($PTR != NULL) {}) UNION FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR[$IDX] WHERE NOT (if($PTR != NULL) {}) DIFFERENCE FIND $RT $FNAME($PT * $PTR) {} CONTAINS if($PTR != NULL) {}'

{ time {
    UNSAFE_CALLEES=$(srcml "$XML" \
        --srcql "$PASS1_QUERY" \
        -q | xmllint --xpath \
        '//*[local-name()="function"]/*[local-name()="name"]' \
        - 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$' || true)
}; } 2>&1
echo

if [ -z "$UNSAFE_CALLEES" ]; then
    echo "[ interprocedural ] No unsafe callees found."
    exit 0
fi

echo "    candidate callees:"
echo "$UNSAFE_CALLEES" | while IFS= read -r name; do
    echo "      $name"
done
echo

# -----------------------------------------------------------------------
# Write callee-level smell warning for each unsafe callee
# -----------------------------------------------------------------------
while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    CALLEE_RESULT=$(srcml "$XML" \
        --srcql "FIND \$RT ${CALLEE}(\$PT * \$PTR) {}" \
        -q 2>/dev/null)

    FILENAME=$(echo "$CALLEE_RESULT" | xmllint --xpath \
        'string(//*[local-name()="unit"]/@filename)' - 2>/dev/null)

    CALLEE_POS=$(echo "$CALLEE_RESULT" | xmllint --xpath \
        'string(//*[local-name()="function"]/@*[local-name()="start"])' \
        - 2>/dev/null)

    CALLEE_LINE=$(echo "$CALLEE_POS" | cut -d: -f1)
    CALLEE_COL=$(echo  "$CALLEE_POS" | cut -d: -f2)
    CALLEE_LINE=${CALLEE_LINE:-1}
    CALLEE_COL=${CALLEE_COL:-1}

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "interprocedural" \
        --severity  "warning" \
        --classification  "smell" \
        --rule      "missingNullCheck" \
        --file      "$FILENAME" \
        --line      "$CALLEE_LINE" \
        --col       "$CALLEE_COL" \
        --varname   "$CALLEE" \
        --note-msg  "Function '${CALLEE}' dereferences pointer parameter without internal null check"

    FOUND_COUNT=$((FOUND_COUNT + 1))
    echo "    CALLEE SMELL: ${CALLEE} at ${CALLEE_LINE}:${CALLEE_COL}"

done <<< "$UNSAFE_CALLEES"
echo

# -----------------------------------------------------------------------
# Pass 2: for each callee find callers at two severity levels
# -----------------------------------------------------------------------
echo "--- Pass 2: classifying callers by severity ---"

while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    # Pass 2a — ERROR: caller provably passes NULL
    P2A_RESULT=$(srcml "$XML" \
        --srcql "FIND \$T \$FUNC() {} CONTAINS \$PTR = NULL FOLLOWED BY ${CALLEE}(\$PTR) WHERE NOT (if(\$PTR != NULL) {})" \
        -q 2>/dev/null)

    if [ -n "$(echo "$P2A_RESULT" | grep '<function')" ]; then
        FILENAME=$(echo "$P2A_RESULT" | xmllint --xpath \
            'string(//*[local-name()="unit"]/@filename)' - 2>/dev/null)
        CALLER_NAME=$(echo "$P2A_RESULT" | xmllint --xpath \
            'string(//*[local-name()="function"]/*[local-name()="name"])' \
            - 2>/dev/null)
        CALL_POS=$(get_call_pos "$P2A_RESULT" "$CALLEE")
        CALL_LINE=$(echo "$CALL_POS" | cut -d: -f1)
        CALL_COL=$(echo  "$CALL_POS" | cut -d: -f2)

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "interprocedural" \
            --severity  "error" \
            --classification  "vulnerability" \
            --rule      "nullPointer" \
            --file      "$FILENAME" \
            --line      "$CALL_LINE" \
            --col       "$CALL_COL" \
            --varname   "$CALLEE" \
            --note-msg  "Null pointer passed to '${CALLEE}' which dereferences without guard"

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    ERROR:   ${CALLER_NAME} → ${CALLEE} at ${CALL_LINE}:${CALL_COL} (passes NULL)"
    fi

    # Pass 2b — WARNING: caller passes unguarded pointer
    P2B_RESULT=$(srcml "$XML" \
        --srcql "FIND \$T \$FUNC() {} CONTAINS \$PT * \$PTR FOLLOWED BY ${CALLEE}(\$PTR) WHERE NOT (if(\$PTR != NULL) {}) DIFFERENCE FIND \$T \$FUNC() {} CONTAINS \$PTR = NULL FOLLOWED BY ${CALLEE}(\$PTR) DIFFERENCE FIND \$T \$FUNC() {} CONTAINS if(\$PTR != NULL) { ${CALLEE}(\$PTR); }" \
        -q 2>/dev/null)

    if [ -n "$(echo "$P2B_RESULT" | grep '<function')" ]; then
        FILENAME=$(echo "$P2B_RESULT" | xmllint --xpath \
            'string(//*[local-name()="unit"]/@filename)' - 2>/dev/null)
        CALLER_NAME=$(echo "$P2B_RESULT" | xmllint --xpath \
            'string(//*[local-name()="function"]/*[local-name()="name"])' \
            - 2>/dev/null)
        CALL_POS=$(get_call_pos "$P2B_RESULT" "$CALLEE")
        CALL_LINE=$(echo "$CALL_POS" | cut -d: -f1)
        CALL_COL=$(echo  "$CALL_POS" | cut -d: -f2)

        write_finding \
            --findings  "$FINDINGS" \
            --detector  "interprocedural" \
            --severity  "warning" \
            --classification  "smell" \
            --rule      "missingNullCheck" \
            --file      "$FILENAME" \
            --line      "$CALL_LINE" \
            --col       "$CALL_COL" \
            --varname   "$CALLEE" \
            --note-msg  "Unguarded pointer passed to '${CALLEE}' which dereferences without guard"

        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "    WARNING: ${CALLER_NAME} → ${CALLEE} at ${CALL_LINE}:${CALL_COL} (unguarded ptr)"
    fi

done <<< "$UNSAFE_CALLEES"

echo
echo "[ interprocedural ] $FOUND_COUNT finding(s) written to $FINDINGS"