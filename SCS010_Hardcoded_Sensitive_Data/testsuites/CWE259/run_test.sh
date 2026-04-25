#!/usr/bin/env bash
# run_test.sh — SCS010 CWE-259 Hardcoded Sensitive Data test suite
# Usage: cd testsuites/CWE259 && bash run_test.sh
#
# Expected:
#   bad_*   → at least one finding, any severity (TP)
#   good_*  → zero findings (TN)
#
# Note: all SCS010 findings are error/vulnerability (hardcoded credentials are
#       always exploitable by design). No smell_ variants exist for this detector.
#
# Interprocedural structure (inverted vs. other SCSes):
#   22a: contains the hardcoded literal → detectable, tested as bad (tier2)
#   22b: contains only the sink/use, no literal → known FN limitation (tier3)
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
        echo "NOTE  $label — missed as expected (sink-only file — known limitation)"
    fi
}

echo "========================================"
echo " SCS010 CWE-259 Hardcoded Sensitive Data Test Suite"
echo "========================================"
echo

# ---------------------------------------------------------------------------
# TIER 1 — Smell pattern variants
# ---------------------------------------------------------------------------
echo "--- TIER 1: Smell pattern variants ---"
echo

echo "--- Detector 1: password_var ---"
run_bad  "bad_password_var_01"  "$SCRIPT_DIR/password_var/bad_password_var_01.c"
run_good "good_password_var_01" "$SCRIPT_DIR/password_var/good_password_var_01.c"
echo

echo "--- Detector 2: define_const ---"
run_bad  "bad_define_const_01"  "$SCRIPT_DIR/define_const/bad_define_const_01.c"
run_good "good_define_const_01" "$SCRIPT_DIR/define_const/good_define_const_01.c"
echo

echo "--- Detector 3: strcmp_auth ---"
run_bad  "bad_strcmp_auth_01"  "$SCRIPT_DIR/strcmp_auth/bad_strcmp_auth_01.c"
run_good "good_strcmp_auth_01" "$SCRIPT_DIR/strcmp_auth/good_strcmp_auth_01.c"
echo

# ---------------------------------------------------------------------------
# TIER 2 — Context variants
# ---------------------------------------------------------------------------
echo "--- TIER 2: Context variants ---"
echo

echo "--- Interprocedural (source-side: literal is in 22a) ---"
run_bad  "bad_password_interprocedural_22a"  "$SCRIPT_DIR/interprocedural/bad_password_interprocedural_22a.c"
run_good "good_password_interprocedural_22b" "$SCRIPT_DIR/interprocedural/good_password_interprocedural_22b.c"
echo

echo "--- C++ class variant ---"
run_bad  "bad_password_class_84"  "$SCRIPT_DIR/cpp_class/bad_password_class_84.cpp"
run_good "good_password_class_84" "$SCRIPT_DIR/cpp_class/good_password_class_84.cpp"
echo

# ---------------------------------------------------------------------------
# TIER 3 — Known limitation cases (excluded from pass/fail counts)
# ---------------------------------------------------------------------------
echo "--- TIER 3: Known limitation cases ---"
echo "    (22b file contains only the sink/use — no credential literal present;"
echo "     single-file analysis cannot detect the pattern here)"
echo
run_limitation "bad_password_interprocedural_22b" "$SCRIPT_DIR/interprocedural/bad_password_interprocedural_22b.c"
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
