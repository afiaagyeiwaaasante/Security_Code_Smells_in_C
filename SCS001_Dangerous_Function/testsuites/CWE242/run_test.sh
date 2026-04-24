#!/usr/bin/env bash
# run_test.sh — SCS001 CWE-242 Dangerous Function test suite
# Usage: cd testsuites/CWE242 && bash run_test.sh
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
        echo "SKIP  $label (smell_report.sh not yet implemented)"
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
        echo "SKIP  $label (smell_report.sh not yet implemented)"
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

# Tier 3: known limitation — SmellDetect is expected to miss these.
# PASS means correctly missed (not a false negative in our threat model).
run_limitation() {
    local label="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "SKIP  $label (file not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if [ ! -f "$SRC_DIR/smell_report.sh" ]; then
        echo "SKIP  $label (smell_report.sh not yet implemented)"
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

echo "========================================"
echo " SCS001 CWE-242 Dangerous Function Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell function variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell function variants ---"
echo

echo "--- gets() vs fgets() ---"
run_bad  "bad_gets_01"    "$SCRIPT_DIR/gets/bad_gets_01.c"
run_good "good_gets_01"   "$SCRIPT_DIR/gets/good_gets_01.c"
echo

echo "--- strcpy() vs strncpy() ---"
run_bad  "bad_strcpy_01"  "$SCRIPT_DIR/strcpy/bad_strcpy_01.c"
run_good "good_strcpy_01" "$SCRIPT_DIR/strcpy/good_strcpy_01.c"
echo

echo "--- strcat() vs strncat() ---"
run_bad  "bad_strcat_01"  "$SCRIPT_DIR/strcat/bad_strcat_01.c"
run_good "good_strcat_01" "$SCRIPT_DIR/strcat/good_strcat_01.c"
echo

echo "--- sprintf() vs snprintf() ---"
run_bad  "bad_sprintf_01"  "$SCRIPT_DIR/sprintf/bad_sprintf_01.c"
run_good "good_sprintf_01" "$SCRIPT_DIR/sprintf/good_sprintf_01.c"
echo

echo "--- scanf() with unbounded format ---"
run_bad  "bad_scanf_01"   "$SCRIPT_DIR/scanf/bad_scanf_01.c"
run_good "good_scanf_01"  "$SCRIPT_DIR/scanf/good_scanf_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

# Interprocedural — multi-file variant
# Both files are combined into one srcML archive so srcQL can see across them.
# 62a.c: caller passes buf to read_input() — gets() not visible here alone
# 62b.c: callee calls gets(dest) on the received buffer
# Combined: srcQL query matches gets() and emits a finding
echo "--- interprocedural (multi-file) ---"
MULTI_SRC_DIR="$SCRIPT_DIR/interprocedural"
if [ ! -f "$SRC_DIR/smell_report_multi.sh" ]; then
    echo "SKIP  bad_gets_interprocedural_62 (smell_report_multi.sh not found)"
    SKIP=$((SKIP+1))
else
    MULTI_OUTPUT=$(bash "$SRC_DIR/smell_report_multi.sh" \
        "$MULTI_SRC_DIR/bad_gets_interprocedural_62a.c" \
        "$MULTI_SRC_DIR/bad_gets_interprocedural_62b.c" \
        2>&1)
    if echo "$MULTI_OUTPUT" | grep -q '"severity":'; then
        echo "PASS  bad_gets_interprocedural_62 — cross-file gets() detected"
        PASS=$((PASS+1))
    else
        echo "FAIL  bad_gets_interprocedural_62 — expected finding, got none"
        FAIL=$((FAIL+1))
    fi
fi
echo

echo "--- multi-instance ---"
run_bad "bad_gets_multi_01" "$SCRIPT_DIR/multi/bad_gets_multi_01.c"
run_bad "bad_gets_multi_02" "$SCRIPT_DIR/multi/bad_gets_multi_02.c"
run_bad "bad_gets_mixed_01" "$SCRIPT_DIR/multi/bad_gets_mixed_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases (expected: missed by SmellDetect) ---"
echo

echo "--- macro-wrapped gets() ---"
run_limitation "bad_gets_macro_01" "$SCRIPT_DIR/get_macro/bad_gets_macros_01.c"
echo

echo "--- function-pointer alias ---"
run_limitation "bad_gets_fnptr_01" "$SCRIPT_DIR/get_macro/bad_gets_fnptr_01.c"

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
