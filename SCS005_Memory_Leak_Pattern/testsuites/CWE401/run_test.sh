#!/usr/bin/env bash
# run_test.sh — SCS005 CWE-401 Memory Leak Pattern test suite
# Usage: cd testsuites/CWE401 && bash run_test.sh
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

run_limitation() {
    local label="$1"
    local file="$2"
    local expected="$3"   # "missed" or "clean"
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
    if [ "$expected" = "missed" ]; then
        if echo "$output" | grep -q '"severity":'; then
            echo "NOTE  $label — unexpectedly detected (limitation resolved?)"
        else
            echo "NOTE  $label — missed as expected (known limitation)"
        fi
    else
        if echo "$output" | grep -q '"severity":'; then
            echo "NOTE  $label — false positive on limitation case"
        else
            echo "NOTE  $label — clean as expected"
        fi
    fi
}

echo "========================================"
echo " SCS005 CWE-401 Memory Leak Pattern Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 1: no_free_on_exit ---"
run_bad  "bad_malloc_no_free_01"    "$SCRIPT_DIR/int/bad_malloc_no_free_01.c"
run_good "good_malloc_with_free_01" "$SCRIPT_DIR/int/good_malloc_with_free_01.c"
echo

echo "--- Detector 2: overwrite_leak ---"
run_bad  "bad_overwrite_01"  "$SCRIPT_DIR/overwrite/bad_overwrite_01.c"
run_good "good_overwrite_01" "$SCRIPT_DIR/overwrite/good_overwrite_01.c"
echo

echo "--- Detector 3: new_no_delete ---"
run_bad  "bad_new_no_delete_01"  "$SCRIPT_DIR/new_delete/bad_new_no_delete_01.cpp"
run_good "good_new_delete_01"    "$SCRIPT_DIR/new_delete/good_new_delete_01.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (Detector 1 misses early-return leaks: free() on normal path"
echo "     suppresses detection — documented in docs/known_issues.md)"
echo
run_limitation "bad_early_return_01"  "$SCRIPT_DIR/early_return/bad_early_return_01.c"  "missed"
run_limitation "good_early_return_01" "$SCRIPT_DIR/early_return/good_early_return_01.c" "clean"
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
