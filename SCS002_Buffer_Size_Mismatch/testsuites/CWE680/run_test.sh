#!/usr/bin/env bash
# run_test.sh — SCS002 CWE-680 Buffer Size Mismatch test suite
# Usage: cd testsuites/CWE680 && bash run_test.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../../src"
PASS=0
FAIL=0
SKIP=0

run_bad_multi() {
    local label="$1"
    shift
    local files=("$@")
    for f in "${files[@]}"; do
        if [ ! -f "$f" ]; then
            echo "SKIP  $label (file not found: $(basename $f))"
            SKIP=$((SKIP+1))
            return
        fi
    done
    if [ ! -f "$SRC_DIR/smell_report_multi.sh" ]; then
        echo "SKIP  $label (smell_report_multi.sh not found)"
        SKIP=$((SKIP+1))
        return
    fi
    output=$(bash "$SRC_DIR/smell_report_multi.sh" "${files[@]}" 2>&1)
    if echo "$output" | grep -q '"severity":'; then
        echo "PASS  $label"
        PASS=$((PASS+1))
    else
        echo "FAIL  $label — no finding emitted"
        FAIL=$((FAIL+1))
    fi
}

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

echo "========================================"
echo " SCS002 CWE-680 Buffer Size Mismatch Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# Detector — buffer_size_mismatch (malloc with multiplication)
# ---------------------------------------------------------------------------
echo "--- malloc(n * sizeof) vs calloc(n, sizeof) — baseline ---"
run_bad  "bad_malloc_01"          "$SCRIPT_DIR/malloc/bad_malloc_01.c"
run_good "good_malloc_01"         "$SCRIPT_DIR/malloc/good_malloc_01.c"
run_good "good_malloc_01_guarded" "$SCRIPT_DIR/malloc/good_malloc_01_guarded.c"

echo
echo "--- fixed data source ---"
run_bad  "bad_malloc_fixed_01"          "$SCRIPT_DIR/malloc/bad_malloc_fixed_01.c"
run_good "good_malloc_fixed_01"         "$SCRIPT_DIR/malloc/good_malloc_fixed_01.c"
run_good "good_malloc_fixed_01_guarded" "$SCRIPT_DIR/malloc/good_malloc_fixed_01_guarded.c"

echo
echo "--- fgets data source ---"
run_bad  "bad_malloc_fgets_01"          "$SCRIPT_DIR/malloc/bad_malloc_fgets_01.c"
run_good "good_malloc_fgets_01"         "$SCRIPT_DIR/malloc/good_malloc_fgets_01.c"
run_good "good_malloc_fgets_01_guarded" "$SCRIPT_DIR/malloc/good_malloc_fgets_01_guarded.c"

echo
echo "--- rand data source ---"
run_bad  "bad_malloc_rand_01"          "$SCRIPT_DIR/malloc/bad_malloc_rand_01.c"
run_good "good_malloc_rand_01"         "$SCRIPT_DIR/malloc/good_malloc_rand_01.c"
run_good "good_malloc_rand_01_guarded" "$SCRIPT_DIR/malloc/good_malloc_rand_01_guarded.c"

echo
echo "--- interprocedural ---"
run_bad  "bad_malloc_return_01"     "$SCRIPT_DIR/interprocedural/bad_malloc_return_01.c"
run_bad_multi "bad_malloc_interproc_01" \
    "$SCRIPT_DIR/interprocedural/bad_malloc_interproc_01a.c" \
    "$SCRIPT_DIR/interprocedural/bad_malloc_interproc_01b.c"
run_good "good_malloc_interproc_01" "$SCRIPT_DIR/interprocedural/good_malloc_interproc_01.c"

echo
echo "--- precomputed size (detect_precomputed_size detector) ---"
run_bad  "bad_malloc_precomputed_01"  "$SCRIPT_DIR/malloc/bad_malloc_precomputed_01.c"
run_good "good_malloc_precomputed_01" "$SCRIPT_DIR/malloc/good_malloc_precomputed_01.c"

echo
echo "--- struct member (expected: MISSED = false negative) ---"
run_bad  "bad_malloc_struct_01"  "$SCRIPT_DIR/struct/bad_malloc_struct_01.c"
run_good "good_malloc_struct_01" "$SCRIPT_DIR/struct/good_malloc_struct_01.c"

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
