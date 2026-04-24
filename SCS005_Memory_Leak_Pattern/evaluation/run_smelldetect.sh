#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS005 tool on each CWE-401 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE401"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"

> "$RESULTS"

echo "========================================"
echo " SCS005 — SmellDetect Benchmark"
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

echo "--- Detector 1: no_free_on_exit ---"
run_case "bad_malloc_no_free_01"    "tier1" "bad"  "$TESTSUITE/int/bad_malloc_no_free_01.c"
run_case "good_malloc_with_free_01" "tier1" "good" "$TESTSUITE/int/good_malloc_with_free_01.c"
echo

echo "--- Detector 2: overwrite_leak ---"
run_case "bad_overwrite_01"  "tier1" "bad"  "$TESTSUITE/overwrite/bad_overwrite_01.c"
run_case "good_overwrite_01" "tier1" "good" "$TESTSUITE/overwrite/good_overwrite_01.c"
echo

echo "--- Detector 3: new_no_delete ---"
run_case "bad_new_no_delete_01"  "tier1" "bad"  "$TESTSUITE/new_delete/bad_new_no_delete_01.cpp"
run_case "good_new_delete_01"    "tier1" "good" "$TESTSUITE/new_delete/good_new_delete_01.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (expected: MISSED) ==="
echo

echo "--- Detector 1: no_free_on_exit (early-return path) ---"
run_case "bad_early_return_01"  "tier3" "bad"  "$TESTSUITE/early_return/bad_early_return_01.c"
run_case "good_early_return_01" "tier3" "good" "$TESTSUITE/early_return/good_early_return_01.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
