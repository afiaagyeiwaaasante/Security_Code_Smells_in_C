#!/usr/bin/env bash
# run_test.sh — SCS007 CWE-195 Signed/Unsigned Confusion test suite
# Usage: cd testsuites/CWE195 && bash run_test.sh
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
        echo "NOTE  $label — unexpectedly detected (limitation resolved?)"
    else
        echo "NOTE  $label — missed as expected (source-only file — known limitation)"
    fi
}

echo "========================================"
echo " SCS007 CWE-195 Signed/Unsigned Confusion Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 1: signed_malloc (malloc_size) ---"
run_bad   "bad_malloc_size_01"    "$SCRIPT_DIR/malloc_size/bad_malloc_size_01.c"
run_good  "good_malloc_size_01"   "$SCRIPT_DIR/malloc_size/good_malloc_size_01.c"
run_smell "smell_malloc_size_01"  "$SCRIPT_DIR/malloc_size/smell_malloc_size_01.c"
echo

echo "--- Detector 2: signed_memcpy (memcpy_count) ---"
run_bad   "bad_memcpy_count_01"    "$SCRIPT_DIR/memcpy_count/bad_memcpy_count_01.c"
run_good  "good_memcpy_count_01"   "$SCRIPT_DIR/memcpy_count/good_memcpy_count_01.c"
run_smell "smell_memcpy_count_01"  "$SCRIPT_DIR/memcpy_count/smell_memcpy_count_01.c"
echo

echo "--- Detector 3: signed_strncpy (strncpy_count) ---"
run_bad   "bad_strncpy_count_01"    "$SCRIPT_DIR/strncpy_count/bad_strncpy_count_01.c"
run_good  "good_strncpy_count_01"   "$SCRIPT_DIR/strncpy_count/good_strncpy_count_01.c"
run_smell "smell_strncpy_count_01"  "$SCRIPT_DIR/strncpy_count/smell_strncpy_count_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- Detector 1: signed_malloc (interprocedural sink-side) ---"
run_bad  "bad_signed_malloc_22b"   "$SCRIPT_DIR/interprocedural/bad_signed_malloc_22b.c"
run_good "good_signed_malloc_22b"  "$SCRIPT_DIR/interprocedural/good_signed_malloc_22b.c"
echo

echo "--- Detector 1: signed_malloc (C++ class variant) ---"
run_bad  "bad_signed_malloc_84"   "$SCRIPT_DIR/cpp_class/bad_signed_malloc_84.cpp"
run_good "good_signed_malloc_84"  "$SCRIPT_DIR/cpp_class/good_signed_malloc_84.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (22a files contain only the taint source — no sink call present;"
echo "     single-file analysis cannot detect the pattern here)"
echo
run_limitation "bad_signed_malloc_22a"   "$SCRIPT_DIR/interprocedural/bad_signed_malloc_22a.c"
run_limitation "good_signed_malloc_22a"  "$SCRIPT_DIR/interprocedural/good_signed_malloc_22a.c"
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
