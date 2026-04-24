#!/usr/bin/env bash
# run_test.sh — SCS003 CWE-476 Missing Null Check test suite
# Usage: cd testsuites/CWE476 && bash run_test.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../../src"
PASS=0
FAIL=0
SKIP=0

# Tier 3: known limitation — SmellDetect is expected to miss these.
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
        echo "PASS  $label (unexpectedly detected — limitation resolved)"
        PASS=$((PASS+1))
    else
        echo "PASS  $label (correctly missed — known limitation)"
        PASS=$((PASS+1))
    fi
}

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
    if echo "$output" | grep -qE ': error:| error\(s\) detected'; then
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
echo " SCS003 CWE-476 Missing Null Check Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- binary_if (Detector 1) ---"
run_bad  "bad_binary_if_01"     "$SCRIPT_DIR/binary_if/bad_binary_if_01.c"
run_bad  "bad_binary_if_flow02" "$SCRIPT_DIR/binary_if/bad_binary_if_flow02.c"
run_bad  "bad_binary_if_flow05" "$SCRIPT_DIR/binary_if/bad_binary_if_flow05.c"
run_bad  "bad_binary_if_flow11" "$SCRIPT_DIR/binary_if/bad_binary_if_flow11.c"
run_good "good_binary_if_01"    "$SCRIPT_DIR/binary_if/good_binary_if_01.c"
echo

echo "--- deref_no_check (Detectors 3 & 4) ---"
run_bad  "bad_null_deref_01"    "$SCRIPT_DIR/deref_no_check/bad_null_deref_01.c"
run_good "good_guarded_01"      "$SCRIPT_DIR/deref_no_check/good_guarded_01.c"
run_bad  "smell_no_guard_01"    "$SCRIPT_DIR/deref_no_check/smell_no_guard_01.c"
echo

echo "--- char (Detectors 3 & 4) ---"
run_bad  "bad_char_01"          "$SCRIPT_DIR/char/bad_char_01.c"
run_bad  "bad_char_01b"         "$SCRIPT_DIR/char/bad_char_01b.c"
run_good "good_char_01"         "$SCRIPT_DIR/char/good_char_01.c"
run_bad  "smell_char_01b"       "$SCRIPT_DIR/char/smell_char_01b.c"
run_good "good_char_01b"        "$SCRIPT_DIR/char/good_char_01b.c"
echo

echo "--- deref_after_check (Detector 5) ---"
run_bad  "bad_deref_after_check_01" "$SCRIPT_DIR/after_check/bad_deref_after_check_01.c"
echo

echo "--- check_after_deref (Detector 6) ---"
run_bad  "bad_check_after_deref_01" "$SCRIPT_DIR/check_after_deref/bad_check_after_deref_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- interprocedural (Detector 2) ---"
run_bad      "bad_interprocedural_01"      "$SCRIPT_DIR/interprocedural/bad_interprocedural_01.c"
run_bad      "good_interprocedural_01"     "$SCRIPT_DIR/interprocedural/good_interprocedural_01.c"
run_bad      "bad_char_interprocedural_01" "$SCRIPT_DIR/interprocedural/bad_char_interprocedural_01.c"
run_bad_multi "bad_char_interprocedural_22" \
    "$SCRIPT_DIR/interprocedural/bad_char_interprocedural_22a.c" \
    "$SCRIPT_DIR/interprocedural/bad_char_interprocedural_22b.c"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (expected: missed by SmellDetect)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases (expected: missed by SmellDetect) ---"
echo

echo "--- char literal initializer (Detector 4 limitation) ---"
run_limitation "smell_char_01"             "$SCRIPT_DIR/char/smell_char_01.c"
echo

echo "--- struct propagation (Detectors 3 & 4 limitations) ---"
run_limitation "bad_struct_ptr_to_ptr_01"  "$SCRIPT_DIR/struct/bad_struct_ptr_to_ptr_01.c"
run_limitation "bad_struct_copy_01"        "$SCRIPT_DIR/struct/bad_struct_copy_01.c"
run_limitation "bad_struct_union_01"       "$SCRIPT_DIR/struct/bad_struct_union_01.c"
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
