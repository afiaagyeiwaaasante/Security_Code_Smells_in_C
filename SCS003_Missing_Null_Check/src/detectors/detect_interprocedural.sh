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
#
#   Pass 2a — error: for each callee, find callers that pass NULL
#   Pass 2b — warning: for each callee, find callers that pass any
#              unguarded pointer, minus those already found by 2a
#
# Requires: srcml, xmllint
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: interprocedural ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

# Read source lines once
SRC_LINES=()
while IFS= read -r line; do
    SRC_LINES+=("$line")
done < "$SRC"

FOUND_COUNT=0

# -----------------------------------------------------------------------
# Helper: write one finding to FINDINGS file
# -----------------------------------------------------------------------
write_finding() {
    local SEVERITY=$1
    local RULE=$2
    local FILENAME=$3
    local CALL_LINE=$4
    local CALL_COL=$5
    local CALLEE=$6
    local SOURCE_LINE=$7
    local NOTE_MSG=$8

    local SOURCE_LINE_ESC
    SOURCE_LINE_ESC=$(echo "$SOURCE_LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')

    cat >> "$FINDINGS" << EOF
{
  "detector": "interprocedural",
  "severity": "${SEVERITY}",
  "rule": "${RULE}",
  "file": "${FILENAME}",
  "line": ${CALL_LINE},
  "col": ${CALL_COL},
  "source_line": "${SOURCE_LINE_ESC}",
  "varname": "${CALLEE}",
  "note": {
    "line": ${CALL_LINE},
    "col": ${CALL_COL},
    "source_line": "${SOURCE_LINE_ESC}",
    "message": "${NOTE_MSG}"
  }
}
EOF
    FOUND_COUNT=$((FOUND_COUNT + 1))
}

# -----------------------------------------------------------------------
# Helper: extract call position from srcQL result
# -----------------------------------------------------------------------
get_call_pos() {
    local RESULT=$1
    local CALLEE=$2

    local POS
    POS=$(echo "$RESULT" | xmllint --xpath \
        "//*[local-name()='call'][*[local-name()='name'][.='${CALLEE}']]/@*[local-name()='start']" \
        - 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)

    # Fall back to function start
    if [ -z "$POS" ]; then
        POS=$(echo "$RESULT" | xmllint --xpath \
            'string(//*[local-name()="function"]/@*[local-name()="start"])' \
            - 2>/dev/null)
    fi

    echo "${POS:-1:1}"
}

# -----------------------------------------------------------------------
# Pass 1: find unsafe callees
# Callees that dereference a pointer parameter without any null check.
# UNION covers both -> and [] dereference tokens.
# DIFFERENCE excludes callees that have if($PTR != NULL) inside.
# -----------------------------------------------------------------------
echo "--- Pass 1: finding unsafe callees ---"

PASS1_QUERY='FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR->$FIELD WHERE NOT (if($PTR != NULL) {}) UNION FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR[$IDX] WHERE NOT (if($PTR != NULL) {}) DIFFERENCE FIND $RT $FNAME($PT * $PTR) {} CONTAINS if($PTR != NULL) {}'

{ time {
    UNSAFE_CALLEES=$(srcml "$XML" \
        --srcql "$PASS1_QUERY" \
        -q | xmllint --xpath \
        '//*[local-name()="function"]/*[local-name()="name"]' \
        - 2>/dev/null | sed 's/<[^>]*>//g' | grep -v '^$')
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

# After Pass 1 collects UNSAFE_CALLEES, write a warning for each callee itself
while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    # Find the callee function position
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

    SOURCE_LINE="${SRC_LINES[$((CALLEE_LINE - 1))]}"

    write_finding "warning" "missingNullCheck" \
        "$FILENAME" "$CALLEE_LINE" "$CALLEE_COL" "$CALLEE" \
        "$SOURCE_LINE" \
        "Function '${CALLEE}' dereferences pointer parameter without internal null check"

    echo "    CALLEE SMELL: ${CALLEE} at ${CALLEE_LINE}:${CALLEE_COL} — no internal null check"

done <<< "$UNSAFE_CALLEES"

# -----------------------------------------------------------------------
# Pass 2: for each callee find callers at two severity levels
# -----------------------------------------------------------------------
echo "--- Pass 2: classifying callers by severity ---"

while IFS= read -r CALLEE; do
    [ -z "$CALLEE" ] && continue

    # ------------------------------------------------------------------
    # Pass 2a — ERROR: caller provably passes NULL to callee
    # Covers both assignment style (ptr = NULL) and declaration with
    # initializer ($TYPE $PTR = NULL)
    # ------------------------------------------------------------------
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
        SOURCE_LINE="${SRC_LINES[$((CALL_LINE - 1))]}"

        write_finding "error" "nullPointer" \
            "$FILENAME" "$CALL_LINE" "$CALL_COL" "$CALLEE" \
            "$SOURCE_LINE" \
            "Null pointer passed to '${CALLEE}' which dereferences without guard"

        echo "    ERROR:   ${CALLER_NAME} → ${CALLEE} at ${CALL_LINE}:${CALL_COL} (passes NULL)"
    fi

    # ------------------------------------------------------------------
    # Pass 2b — WARNING: caller passes unguarded pointer, not NULL
    # DIFFERENCE subtracts the NULL case already caught by 2a
    # Covers both uninitialized ptr and non-NULL assigned ptr
    # ------------------------------------------------------------------
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
        SOURCE_LINE="${SRC_LINES[$((CALL_LINE - 1))]}"

        write_finding "warning" "missingNullCheck" \
            "$FILENAME" "$CALL_LINE" "$CALL_COL" "$CALLEE" \
            "$SOURCE_LINE" \
            "Unguarded pointer passed to '${CALLEE}' which dereferences without guard"

        echo "    WARNING: ${CALLER_NAME} → ${CALLEE} at ${CALL_LINE}:${CALL_COL} (unguarded ptr)"
    fi

done <<< "$UNSAFE_CALLEES"

echo
echo "[ interprocedural ] $FOUND_COUNT finding(s) written to $FINDINGS"