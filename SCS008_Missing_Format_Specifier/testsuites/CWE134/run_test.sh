#!/usr/bin/env bash
# run_test.sh — SCS008 CWE-134 Missing Format Specifier test suite
# Usage: cd testsuites/CWE134 && bash run_test.sh
#
# Expected:
#   bad_*   → at least one finding, any severity (TP)
#   good_*  → zero findings (TN)
#
# Note: all SCS008 findings are error/vulnerability (tainted input to printf-family).
#       No smell_ variants exist for this detector.
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
echo " SCS008 CWE-134 Missing Format Specifier Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 1: printf_direct ---"
run_bad  "bad_printf_direct_01"  "$SCRIPT_DIR/printf_direct/bad_printf_direct_01.c"
run_good "good_printf_direct_01" "$SCRIPT_DIR/printf_direct/good_printf_direct_01.c"
echo

echo "--- Detector 2: fprintf_direct ---"
run_bad  "bad_fprintf_direct_01"  "$SCRIPT_DIR/fprintf_direct/bad_fprintf_direct_01.c"
run_good "good_fprintf_direct_01" "$SCRIPT_DIR/fprintf_direct/good_fprintf_direct_01.c"
echo

echo "--- Detector 1/2: env_format ---"
run_bad  "bad_env_format_01"  "$SCRIPT_DIR/env_format/bad_env_format_01.c"
run_good "good_env_format_01" "$SCRIPT_DIR/env_format/good_env_format_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- Interprocedural (sink-side) ---"
run_bad  "bad_printf_interprocedural_22b"  "$SCRIPT_DIR/interprocedural/bad_printf_interprocedural_22b.c"
run_good "good_printf_interprocedural_22b" "$SCRIPT_DIR/interprocedural/good_printf_interprocedural_22b.c"
echo

echo "--- C++ class variant ---"
run_bad  "bad_printf_class_84"  "$SCRIPT_DIR/cpp_class/bad_printf_class_84.cpp"
run_good "good_printf_class_84" "$SCRIPT_DIR/cpp_class/good_printf_class_84.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (22a files contain only the taint source — no sink call present;"
echo "     single-file analysis cannot detect the pattern here)"
echo
run_limitation "bad_printf_interprocedural_22a"  "$SCRIPT_DIR/interprocedural/bad_printf_interprocedural_22a.c"
run_limitation "good_printf_interprocedural_22a" "$SCRIPT_DIR/interprocedural/good_printf_interprocedural_22a.c"
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
