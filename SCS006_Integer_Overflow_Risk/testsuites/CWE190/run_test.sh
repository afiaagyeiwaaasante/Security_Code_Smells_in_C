#!/usr/bin/env bash
# run_test.sh — SCS006 CWE-190 Integer Overflow Risk test suite
# Usage: cd testsuites/CWE190 && bash run_test.sh
#
# Expected:
#   bad_*   → at least one finding, any severity (TP)
#   good_*  → zero findings (TN)
#   smell_* → at least one finding with severity=warning, classification=smell
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../../src"
PASS=0
FAIL=0
SKIP=0

run_bad() {
    local label="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "SKIP  $label (file not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if [ ! -f "$SRC_DIR/smell_report.sh" ]; then
        echo "SKIP  $label (smell_report.sh not found)"
        SKIP=$((SKIP+1))
        return
    fi
    output=$(bash "$SRC_DIR/smell_report.sh" "$file" 2>&1)
    if echo "$output" | grep -q '"severity":'; then
        echo "PASS  $label"
        PASS=$((PASS+1))
    else
        echo "FAIL  $label — no finding emitted"
        FAIL=$((FAIL+1))
    fi
}

run_good() {
    local label="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "SKIP  $label (file not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if [ ! -f "$SRC_DIR/smell_report.sh" ]; then
        echo "SKIP  $label (smell_report.sh not found)"
        SKIP=$((SKIP+1))
        return
    fi
    output=$(bash "$SRC_DIR/smell_report.sh" "$file" 2>&1)
    if echo "$output" | grep -q '"severity":'; then
        echo "FAIL  $label — false positive"
        FAIL=$((FAIL+1))
    else
        echo "PASS  $label (clean)"
        PASS=$((PASS+1))
    fi
}

run_smell() {
    local label="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "SKIP  $label (file not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if [ ! -f "$SRC_DIR/smell_report.sh" ]; then
        echo "SKIP  $label (smell_report.sh not found)"
        SKIP=$((SKIP+1))
        return
    fi
    output=$(bash "$SRC_DIR/smell_report.sh" "$file" 2>&1)
    if echo "$output" | grep -q '"severity": *"warning"'; then
        echo "PASS  $label (smell)"
        PASS=$((PASS+1))
    elif echo "$output" | grep -q '"severity":'; then
        echo "FAIL  $label — finding emitted but wrong severity (expected warning/smell)"
        FAIL=$((FAIL+1))
    else
        echo "FAIL  $label — no finding emitted"
        FAIL=$((FAIL+1))
    fi
}

run_limitation() {
    local label="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "SKIP  $label (file not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if [ ! -f "$SRC_DIR/smell_report.sh" ]; then
        echo "SKIP  $label (smell_report.sh not found)"
        SKIP=$((SKIP+1))
        return
    fi
    output=$(bash "$SRC_DIR/smell_report.sh" "$file" 2>&1)
    if echo "$output" | grep -q '"severity":'; then
        echo "NOTE  $label — unexpectedly detected on primary file (limitation resolved?)"
    else
        echo "NOTE  $label — missed as expected (interprocedural — known limitation)"
    fi
}

echo "========================================"
echo " SCS006 CWE-190 Integer Overflow Risk Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 2: unchecked_add ---"
run_bad   "bad_char_add_01"           "$SCRIPT_DIR/add/bad_char_add_01.c"
run_good  "good_char_add_01"          "$SCRIPT_DIR/add/good_char_add_01.c"
run_smell "smell_char_add_01"         "$SCRIPT_DIR/add/smell_char_add_01.c"
run_bad   "bad_unsigned_int_add_01"   "$SCRIPT_DIR/add/bad_unsigned_int_add_01.c"
run_good  "good_unsigned_int_add_01"  "$SCRIPT_DIR/add/good_unsigned_int_add_01.c"
echo

echo "--- Detector 1: unchecked_multiply ---"
run_bad   "bad_int_multiply_01"   "$SCRIPT_DIR/multiply/bad_int_multiply_01.c"
run_good  "good_int_multiply_01"  "$SCRIPT_DIR/multiply/good_int_multiply_01.c"
run_smell "smell_int_multiply_01" "$SCRIPT_DIR/multiply/smell_int_multiply_01.c"
echo

echo "--- Detector 1: unchecked_multiply (square variants) ---"
run_bad   "bad_int64_square_01"    "$SCRIPT_DIR/square/bad_int64_square_01.c"
run_good  "good_int64_square_01"   "$SCRIPT_DIR/square/good_int64_square_01.c"
run_smell "smell_int64_square_01"  "$SCRIPT_DIR/square/smell_int64_square_01.c"
run_bad   "bad_short_square_01"    "$SCRIPT_DIR/square/bad_short_square_01.c"
run_good  "good_short_square_01"   "$SCRIPT_DIR/square/good_short_square_01.c"
run_smell "smell_short_square_01"  "$SCRIPT_DIR/square/smell_short_square_01.c"
echo

echo "--- Detector 3: unchecked_increment (postfix) ---"
run_bad   "bad_int_postinc_01"    "$SCRIPT_DIR/postinc/bad_int_postinc_01.c"
run_good  "good_int_postinc_01"   "$SCRIPT_DIR/postinc/good_int_postinc_01.c"
run_smell "smell_int_postinc_01"  "$SCRIPT_DIR/postinc/smell_int_postinc_01.c"
echo

echo "--- Detector 3: unchecked_increment (prefix) ---"
run_bad   "bad_int_preinc_01"    "$SCRIPT_DIR/preinc/bad_int_preinc_01.c"
run_good  "good_int_preinc_01"   "$SCRIPT_DIR/preinc/good_int_preinc_01.c"
run_smell "smell_int_preinc_01"  "$SCRIPT_DIR/preinc/smell_int_preinc_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants (C++ class patterns)
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- Detector 1: unchecked_multiply (C++ class variants) ---"
run_bad  "bad_int_multiply_81"   "$SCRIPT_DIR/cpp_virtual_ref/bad_int_multiply_81.cpp"
run_good "good_int_multiply_81"  "$SCRIPT_DIR/cpp_virtual_ref/good_int_multiply_81.cpp"
run_bad  "bad_int_multiply_82"   "$SCRIPT_DIR/cpp_virtual_ptr/bad_int_multiply_82.cpp"
run_good "good_int_multiply_82"  "$SCRIPT_DIR/cpp_virtual_ptr/good_int_multiply_82.cpp"
run_bad  "bad_int_multiply_83"   "$SCRIPT_DIR/cpp_ctor_stack/bad_int_multiply_83.cpp"
run_good "good_int_multiply_83"  "$SCRIPT_DIR/cpp_ctor_stack/good_int_multiply_83.cpp"
run_bad  "bad_int_multiply_84"   "$SCRIPT_DIR/cpp_ctor_heap/bad_int_multiply_84.cpp"
run_good "good_int_multiply_84"  "$SCRIPT_DIR/cpp_ctor_heap/good_int_multiply_84.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (interprocedural multi-file: primary file only — cross-file detection"
echo "     not supported without smell_report_multi.sh for SCS006)"
echo
run_limitation "bad_int_add_22a"       "$SCRIPT_DIR/interprocedural/bad_int_add_22a.c"
run_limitation "good_int_add_22a"      "$SCRIPT_DIR/interprocedural/good_int_add_22a.c"
run_limitation "bad_int_multiply_22a"  "$SCRIPT_DIR/interprocedural/bad_int_multiply_22a.c"
run_limitation "good_int_multiply_22a" "$SCRIPT_DIR/interprocedural/good_int_multiply_22a.c"
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS+FAIL+SKIP))
echo "========================================"
echo " Results: $PASS/$TOTAL passed  ($FAIL failed, $SKIP skipped)"
echo "========================================"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
