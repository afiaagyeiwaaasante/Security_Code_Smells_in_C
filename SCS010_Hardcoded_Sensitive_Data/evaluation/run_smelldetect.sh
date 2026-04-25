#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS010 tool on each CWE-259 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
#
# Note: all SCS010 findings are error/vulnerability (hardcoded credentials are
#       always exploitable by design). No smell_ variants exist for this detector.
# Note: the interprocedural structure is inverted vs. other SCSes:
#   22a contains the hardcoded literal (detectable, tier2)
#   22b contains only the sink/use  (no literal present, tier3 known limitation)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE259"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"

> "$RESULTS"

echo "========================================"
echo " SCS010 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local FILE="$4"

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    /usr/bin/time -l bash "$SMELL_REPORT" "$FILE" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local FINDING_COUNT DETECTED
    FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
    FINDING_COUNT=${FINDING_COUNT:-0}
    if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi

    printf '{"test":"%s","tier":"%s","expected":"%s","files":["%s"],"detected":%s,"finding_count":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$(basename "$FILE")" \
        "$DETECTED" "$FINDING_COUNT" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected      : $DETECTED"
    echo "    finding count : $FINDING_COUNT"
    echo "    wall time     : ${WALL_TIME}s"
    echo "    peak RSS      : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# -----------------------------------------------------------------------
echo "=== TIER 1: Smell pattern variants ==="
echo

echo "--- Detector 1: password_var ---"
run_case "bad_password_var_01"  "tier1" "bad"  "$TESTSUITE/password_var/bad_password_var_01.c"
run_case "good_password_var_01" "tier1" "good" "$TESTSUITE/password_var/good_password_var_01.c"
echo

echo "--- Detector 2: define_const ---"
run_case "bad_define_const_01"  "tier1" "bad"  "$TESTSUITE/define_const/bad_define_const_01.c"
run_case "good_define_const_01" "tier1" "good" "$TESTSUITE/define_const/good_define_const_01.c"
echo

echo "--- Detector 3: strcmp_auth ---"
run_case "bad_strcmp_auth_01"  "tier1" "bad"  "$TESTSUITE/strcmp_auth/bad_strcmp_auth_01.c"
run_case "good_strcmp_auth_01" "tier1" "good" "$TESTSUITE/strcmp_auth/good_strcmp_auth_01.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- Interprocedural (source-side: literal is in 22a) ---"
run_case "bad_password_interprocedural_22a"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_password_interprocedural_22a.c"
run_case "good_password_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_password_interprocedural_22b.c"
echo

echo "--- C++ class variant ---"
run_case "bad_password_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_password_class_84.cpp"
run_case "good_password_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_password_class_84.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (interprocedural sink-only) ==="
echo "    (22b file contains only the sink/use — no credential literal present;"
echo "     single-file analysis cannot detect the pattern there)"
echo

run_case "bad_password_interprocedural_22b" "tier3" "bad" "$TESTSUITE/interprocedural/bad_password_interprocedural_22b.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
