#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS006 tool on each CWE-190 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
#
# Note: smell_ cases (expected="bad") emit warning/smell severity rather than
#       error/vulnerability — both are counted as detected.
# Note: interprocedural cases (tier3) run on the primary file only; cross-file
#       detection is not supported without smell_report_multi.sh for SCS006.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE190"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"

> "$RESULTS"

echo "========================================"
echo " SCS006 — SmellDetect Benchmark"
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

echo "--- Detector 2: unchecked_add ---"
run_case "bad_char_add_01"           "tier1" "bad"  "$TESTSUITE/add/bad_char_add_01.c"
run_case "good_char_add_01"          "tier1" "good" "$TESTSUITE/add/good_char_add_01.c"
run_case "smell_char_add_01"         "tier1" "bad"  "$TESTSUITE/add/smell_char_add_01.c"
run_case "bad_unsigned_int_add_01"   "tier1" "bad"  "$TESTSUITE/add/bad_unsigned_int_add_01.c"
run_case "good_unsigned_int_add_01"  "tier1" "good" "$TESTSUITE/add/good_unsigned_int_add_01.c"
echo

echo "--- Detector 1: unchecked_multiply ---"
run_case "bad_int_multiply_01"   "tier1" "bad"  "$TESTSUITE/multiply/bad_int_multiply_01.c"
run_case "good_int_multiply_01"  "tier1" "good" "$TESTSUITE/multiply/good_int_multiply_01.c"
run_case "smell_int_multiply_01" "tier1" "bad"  "$TESTSUITE/multiply/smell_int_multiply_01.c"
echo

echo "--- Detector 1: unchecked_multiply (square variants) ---"
run_case "bad_int64_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_int64_square_01.c"
run_case "good_int64_square_01"   "tier1" "good" "$TESTSUITE/square/good_int64_square_01.c"
run_case "smell_int64_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_int64_square_01.c"
run_case "bad_short_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_short_square_01.c"
run_case "good_short_square_01"   "tier1" "good" "$TESTSUITE/square/good_short_square_01.c"
run_case "smell_short_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_short_square_01.c"
echo

echo "--- Detector 3: unchecked_increment (postfix) ---"
run_case "bad_int_postinc_01"    "tier1" "bad"  "$TESTSUITE/postinc/bad_int_postinc_01.c"
run_case "good_int_postinc_01"   "tier1" "good" "$TESTSUITE/postinc/good_int_postinc_01.c"
run_case "smell_int_postinc_01"  "tier1" "bad"  "$TESTSUITE/postinc/smell_int_postinc_01.c"
echo

echo "--- Detector 3: unchecked_increment (prefix) ---"
run_case "bad_int_preinc_01"    "tier1" "bad"  "$TESTSUITE/preinc/bad_int_preinc_01.c"
run_case "good_int_preinc_01"   "tier1" "good" "$TESTSUITE/preinc/good_int_preinc_01.c"
run_case "smell_int_preinc_01"  "tier1" "bad"  "$TESTSUITE/preinc/smell_int_preinc_01.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- Detector 1: unchecked_multiply (C++ class variants) ---"
run_case "bad_int_multiply_81"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ref/bad_int_multiply_81.cpp"
run_case "good_int_multiply_81"  "tier2" "good" "$TESTSUITE/cpp_virtual_ref/good_int_multiply_81.cpp"
run_case "bad_int_multiply_82"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ptr/bad_int_multiply_82.cpp"
run_case "good_int_multiply_82"  "tier2" "good" "$TESTSUITE/cpp_virtual_ptr/good_int_multiply_82.cpp"
run_case "bad_int_multiply_83"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_stack/bad_int_multiply_83.cpp"
run_case "good_int_multiply_83"  "tier2" "good" "$TESTSUITE/cpp_ctor_stack/good_int_multiply_83.cpp"
run_case "bad_int_multiply_84"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_heap/bad_int_multiply_84.cpp"
run_case "good_int_multiply_84"  "tier2" "good" "$TESTSUITE/cpp_ctor_heap/good_int_multiply_84.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (interprocedural multi-file) ==="
echo "    (no smell_report_multi.sh for SCS006 — primary file only)"
echo

run_case "bad_int_add_22"       "tier3" "bad"  "$TESTSUITE/interprocedural/bad_int_add_22a.c"
run_case "good_int_add_22"      "tier3" "good" "$TESTSUITE/interprocedural/good_int_add_22a.c"
run_case "bad_int_multiply_22"  "tier3" "bad"  "$TESTSUITE/interprocedural/bad_int_multiply_22a.c"
run_case "good_int_multiply_22" "tier3" "good" "$TESTSUITE/interprocedural/good_int_multiply_22a.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
