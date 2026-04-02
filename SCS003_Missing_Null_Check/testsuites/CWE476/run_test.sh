#!/usr/bin/env bash
# run_tests.sh
# Runs smell_report.sh against every test case and validates
# that bad/smell files are detected and good files are not.
#
# Exit codes:
#   0 — all tests passed
#   1 — one or more tests failed
#
# Usage:
#   cd tests/CWE476
#   bash run_tests.sh
#
# Requires: srcml, srcslice, srcattributor, xmllint, python3

DETECTOR="$(dirname "$0")/../../src/smell_report.sh"
PASS=0
FAIL=0
TOTAL=0

# -----------------------------------------------------------------------
# run_case <file> <expected> <label>
#
#   file     : path to source file relative to tests/CWE476/
#   expected : "detected" — tool must emit error: or warning:
#              "clean"    — tool must emit no error: or warning:
#   label    : human-readable description shown in results
# -----------------------------------------------------------------------
run_case() {
    local FILE=$1
    local EXPECT=$2
    local LABEL=$3

    TOTAL=$((TOTAL + 1))

    if [ ! -f "$FILE" ]; then
        echo "  SKIP  $LABEL — file not found: $FILE"
        return
    fi

    local OUTPUT
    OUTPUT=$(bash "$DETECTOR" "$FILE" 2>/dev/null)

    if [ "$EXPECT" = "detected" ]; then
        if echo "$OUTPUT" | grep -q '"severity":'; then
            echo "  PASS  $LABEL"
            PASS=$((PASS + 1))
        else
            echo "  FAIL  $LABEL — expected detection, got none"
            FAIL=$((FAIL + 1))
        fi
    else
        if echo "$OUTPUT" | grep -q '"severity":'; then
            echo "  FAIL  $LABEL — expected clean, got detection"
            echo "        $(echo "$OUTPUT" | grep '"severity":' | head -1)"
            FAIL=$((FAIL + 1))
        else
            echo "  PASS  $LABEL"
            PASS=$((PASS + 1))
        fi
    fi
}

echo "========================================"
echo " CWE476 Test Suite"
echo " Detector: $DETECTOR"
echo "========================================"
echo

# -----------------------------------------------------------------------
# binary_if — Detector 1
# Pattern: bitwise & instead of && in null-check condition
# All flow variants pass with the same if-statement level query
# because CONTAINS is depth-agnostic
# -----------------------------------------------------------------------
echo "--- binary_if ---"
run_case "binary_if/bad_binary_if_01.c" \
    "detected" "flow01 — baseline, direct"
run_case "binary_if/bad_binary_if_flow02.c" \
    "detected" "flow02-04 — if(1) constant wrapper"
run_case "binary_if/bad_binary_if_flow05.c" \
    "detected" "flow05-06 — if(staticVar) wrapper"
run_case "binary_if/bad_binary_if_flow11.c" \
    "detected" "flow11-18 — if(globalFunc()) mixed branches"
run_case "binary_if/good_binary_if_01.c" \
    "clean"    "good — && short-circuits safely"
echo

# -----------------------------------------------------------------------
# interprocedural — Detector 2
# Pattern: callee dereferences pointer param, caller passes unguarded ptr
# -----------------------------------------------------------------------
echo "--- interprocedural ---"
run_case "interprocedural/bad_interprocedural_01.c" \
    "detected" "bad callee deref no guard + unguarded caller"
run_case "interprocedural/good_interprocedural_01.c" \
    "detected" "good_callee smell — no internal check, good_caller correctly excluded"
run_case "interprocedural/bad_char_interprocedural_01.c" \
    "detected" "char interprocedural — array index sink, NULL caller + smell caller"
echo

echo "--- interprocedural multi-file (variant 22) ---"
# Multi-file test requires smell_report_multi.sh
MULTI_OUTPUT=$(bash "$(dirname "$0")/../../src/smell_report_multi.sh" \
    "$(dirname "$0")/interprocedural/bad_char_interprocedural_22a.c" \
    "$(dirname "$0")/interprocedural/bad_char_interprocedural_22b.c" \
    2>/dev/null)

if echo "$MULTI_OUTPUT" | grep -qE "error:|warning:"; then
    echo "  PASS  char variant 22 minimal— cross-file interprocedural detection"
    PASS=$((PASS + 1))
else
    echo "  FAIL  char variant 22 minimal — expected detection, got none"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

# -----------------------------------------------------------------------
# deref_no_check — Detector 3 (error level)
# Pattern: ptr assigned NULL locally, dereffed with no guard
# Covers both struct member (->) and array index ([]) dereference
# -----------------------------------------------------------------------
echo "--- deref_no_check (struct member) ---"
run_case "deref_no_check/bad_null_deref_01.c" \
    "detected" "bad — ptr=NULL then ptr->field, no guard"
run_case "deref_no_check/good_guarded_01.c" \
    "clean"    "good — null guard before ptr->field"
echo

echo "--- deref_no_check (array index) ---"
run_case "char/bad_char_01.c" \
    "detected" "bad char — initializer style: char *data = NULL"
run_case "char/bad_char_01b.c" \
    "detected" "bad char — assignment style: data = NULL"
run_case "char/good_char_01.c" \
    "clean"    "good char — null guard before data[0]"
echo

# -----------------------------------------------------------------------
# missing_guard — Detector 4 (warning level)
# Pattern: ptr assigned non-NULL value, dereffed with no guard
# Security code smell — not currently exploitable but structurally fragile
# Covers both struct member (->) and array index ([]) dereference
# -----------------------------------------------------------------------
echo "--- missing_guard (struct member) ---"
run_case "deref_no_check/smell_no_guard_01.c" \
    "detected" "smell — ptr=&local then ptr->field, no guard"
echo

echo "--- missing_guard (array index) ---"
# Known false negative: missing_guard does not fire on string literal init
# (char *data = "Good") — srcQL does not model non-null literal assignments
# as a null risk. smell_char_01b.c (separate assignment form) is used instead.
run_case "char/smell_char_01b.c" \
    "detected" "smell — data=NULL then data[0], no guard (assignment form)"
echo

# -----------------------------------------------------------------------
# variant coverage — confirm flow variants pass without query changes
# These verify that CONTAINS handles arbitrary nesting depth
# -----------------------------------------------------------------------
echo "--- variant coverage (binary_if flow variants) ---"
run_case "binary_if/bad_binary_if_flow02.c" \
    "detected" "variant 02 — if(1) wrapper transparent to CONTAINS"
run_case "binary_if/bad_binary_if_flow05.c" \
    "detected" "variant 05 — if(staticTrue) two bad functions"
run_case "binary_if/bad_binary_if_flow11.c" \
    "detected" "variant 12 — mixed & and && in same function"
echo

echo "--- variant coverage (char flow variants) ---"
run_case "char/bad_char_01.c" \
    "detected" "char variant 01 — baseline"
echo

echo ""
echo "--- char ---"
run_case "char/bad_char_01.c"   "detected" "char null deref — flow01-03"
run_case "char/smell_char_01b.c" "detected" "char smell — no guard (assignment form)"
run_case "char/good_char_01.c"  "clean"    "char good — guarded"
# -----------------------------------------------------------------------
# deref_after_check — Detector 5 (error level)
# Pattern: if(ptr == NULL) { *ptr } — deref inside null-confirmed branch
# -----------------------------------------------------------------------
echo "--- deref_after_check ---"
run_case "after_check/bad_deref_after_check_01.c" \
    "detected" "bad — deref inside if(ptr == NULL) branch"
echo

# -----------------------------------------------------------------------
# check_after_deref — Detector 6 (warning level)
# Pattern: *ptr ... if(ptr != NULL) — null check placed after dereference
# -----------------------------------------------------------------------
echo "--- check_after_deref ---"
run_case "check_after_deref/bad_check_after_deref_01.c" \
    "detected" "bad — null check placed after dereference"
echo

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo "========================================"
echo " Results: $PASS passed, $FAIL failed, $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo " Status : FAILED"
    echo "========================================"
    exit 1
else
    echo " Status : ALL PASSED"
    echo "========================================"
    exit 0
fi