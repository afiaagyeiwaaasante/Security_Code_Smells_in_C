#!/usr/bin/env bash
# run_test.sh — SCS009 CWE-78 Command Injection Risk test suite
# Usage: cd testsuites/CWE78 && bash run_test.sh
#
# Expected:
#   bad_*   → at least one finding, any severity (TP)
#   good_*  → zero findings (TN)
#
# Note: all SCS009 findings are error/vulnerability (tainted input to system/popen/execl).
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
echo " SCS009 CWE-78 Command Injection Risk Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 1: system_console ---"
run_bad  "bad_system_console_01"  "$SCRIPT_DIR/system_console/bad_system_console_01.c"
run_good "good_system_console_01" "$SCRIPT_DIR/system_console/good_system_console_01.c"
echo

echo "--- Detector 2: system_env ---"
run_bad  "bad_system_env_01"  "$SCRIPT_DIR/system_env/bad_system_env_01.c"
run_good "good_system_env_01" "$SCRIPT_DIR/system_env/good_system_env_01.c"
echo

echo "--- Detector 3: popen_console ---"
run_bad  "bad_popen_console_01"  "$SCRIPT_DIR/popen_console/bad_popen_console_01.c"
run_good "good_popen_console_01" "$SCRIPT_DIR/popen_console/good_popen_console_01.c"
echo

echo "--- Detector 4: execl_console ---"
run_bad  "bad_execl_console_01"  "$SCRIPT_DIR/execl_console/bad_execl_console_01.c"
run_good "good_execl_console_01" "$SCRIPT_DIR/execl_console/good_execl_console_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- Interprocedural (sink-side) ---"
run_bad  "bad_system_interprocedural_22b"  "$SCRIPT_DIR/interprocedural/bad_system_interprocedural_22b.c"
run_good "good_system_interprocedural_22b" "$SCRIPT_DIR/interprocedural/good_system_interprocedural_22b.c"
echo

echo "--- C++ class variant ---"
run_bad  "bad_system_class_84"  "$SCRIPT_DIR/cpp_class/bad_system_class_84.cpp"
run_good "good_system_class_84" "$SCRIPT_DIR/cpp_class/good_system_class_84.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (22a file contains only the taint source — no sink call present;"
echo "     single-file analysis cannot detect the pattern here)"
echo
run_limitation "bad_system_interprocedural_22a" "$SCRIPT_DIR/interprocedural/bad_system_interprocedural_22a.c"
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
