#!/usr/bin/env bash
# run_test.sh — SCS004 CWE-416 Use After Free test suite
# Usage: cd testsuites/CWE416 && bash run_test.sh
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
    output=$(bash "$SRC_DIR/smell_report.sh" "$file" 2>&1)
    if echo "$output" | grep -q '"severity":'; then
        echo "FAIL  $label — false positive"
        FAIL=$((FAIL+1))
    else
        echo "PASS  $label (clean)"
        PASS=$((PASS+1))
    fi
}

run_multi_bad() {
    local label="$1"
    shift
    for f in "$@"; do
        if [ ! -f "$f" ]; then
            echo "SKIP  $label (file not found: $f)"
            SKIP=$((SKIP+1))
            return
        fi
    done
    output=$(bash "$SRC_DIR/smell_report_multi.sh" "$@" 2>&1)
    if echo "$output" | grep -qE "error:|warning:"; then
        echo "PASS  $label"
        PASS=$((PASS+1))
    else
        echo "FAIL  $label — no finding emitted"
        FAIL=$((FAIL+1))
    fi
}

echo "========================================"
echo " SCS004 CWE-416 Use After Free Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# Detector 1 — use_after_free
# ---------------------------------------------------------------------------
echo "--- Detector 1: use_after_free ---"
run_bad  "bad_use_after_free_char_01"   "$SCRIPT_DIR/char/bad_use_after_free_char_01.c"
run_good "good_use_after_free_char_01"  "$SCRIPT_DIR/char/good_use_after_free_char_01.c"
run_bad  "bad_use_after_free_int_01"    "$SCRIPT_DIR/int/bad_use_after_free_int_01.c"
run_good "good_use_after_free_int_01"   "$SCRIPT_DIR/int/good_use_after_free_int_01.c"
run_bad  "bad_use_after_free_int64_01"  "$SCRIPT_DIR/int64/bad_use_after_free_int64_01.c"
run_good "good_use_after_free_int64_01" "$SCRIPT_DIR/int64/good_use_after_free_int64_01.c"
run_bad  "bad_use_after_free_long_01"   "$SCRIPT_DIR/long/bad_use_after_free_long_01.c"
run_good "good_use_after_free_long_01"  "$SCRIPT_DIR/long/good_use_after_free_long_01.c"

echo

# ---------------------------------------------------------------------------
# Detector 2 — double_free
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Detector 4 — delete_array_uaf (C++ new[]/delete[])
# ---------------------------------------------------------------------------
echo "--- Detector 4: delete_array_uaf ---"
run_bad  "bad_delete_array_char_01"    "$SCRIPT_DIR/delete_array_char/bad_delete_array_char_01.cpp"
run_good "good_delete_array_char_01"   "$SCRIPT_DIR/delete_array_char/good_delete_array_char_01.cpp"
run_bad  "bad_delete_array_int64_01"  "$SCRIPT_DIR/delete_array_int64_t/bad_delete_array_int64_01.cpp"
run_good "good_delete_array_int64_01" "$SCRIPT_DIR/delete_array_int64_t/good_delete_array_int64_01.cpp"
run_bad  "bad_delete_array_long_01"   "$SCRIPT_DIR/delete_array_long/bad_delete_array_long_01.cpp"
run_good "good_delete_array_long_01"  "$SCRIPT_DIR/delete_array_long/good_delete_array_long_01.cpp"
run_bad  "bad_delete_array_wchar_01"   "$SCRIPT_DIR/delete_array_wchar_t/bad_delete_array_wchar_01.cpp"
run_good "good_delete_array_wchar_01"  "$SCRIPT_DIR/delete_array_wchar_t/good_delete_array_wchar_01.cpp"
run_bad  "bad_delete_array_struct_01"  "$SCRIPT_DIR/delete_array_struct/bad_delete_array_struct_01.cpp"
run_good "good_delete_array_struct_01" "$SCRIPT_DIR/delete_array_struct/good_delete_array_struct_01.cpp"

echo

# ---------------------------------------------------------------------------
# Detector 2 — double_free
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Detector 5 — return_freed_ptr
# ---------------------------------------------------------------------------
echo "--- Detector 5: return_freed_ptr ---"
run_bad  "bad_return_freed_ptr_01"   "$SCRIPT_DIR/freed_pointer/bad_return_freed_ptr_01.c"
run_good "good_return_freed_ptr_01"  "$SCRIPT_DIR/freed_pointer/good_return_freed_ptr_01.c"

echo

# ---------------------------------------------------------------------------
# Detector 2 — double_free
# ---------------------------------------------------------------------------
echo "--- Detector 2: double_free ---"
run_bad  "bad_double_free_01"        "$SCRIPT_DIR/char/bad_double_free_01.c"
run_good "good_double_free_01"       "$SCRIPT_DIR/char/good_double_free_01.c"

echo

# ---------------------------------------------------------------------------
# Detector 3 — interprocedural_uaf (multi-file)
# ---------------------------------------------------------------------------
echo "--- Detector 3: interprocedural_uaf ---"
run_multi_bad "bad_interprocedural_uaf_long_22" \
    "$SCRIPT_DIR/interprocedural/bad_interprocedural_uaf_long_22a.c" \
    "$SCRIPT_DIR/interprocedural/bad_interprocedural_uaf_long_22b.c"
run_multi_bad "bad_interprocedural_delete_array_char_62" \
    "$SCRIPT_DIR/interprocedural/bad_interprocedural_delete_array_char_62a.cpp" \
    "$SCRIPT_DIR/interprocedural/bad_interprocedural_delete_array_char_62b.cpp"

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
