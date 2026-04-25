#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS007 tool on each CWE-195 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
#
# Note: smell_ cases (expected="bad") emit warning/smell severity rather than
#       error/vulnerability — both are counted as detected.
# Note: interprocedural 22a files (tier3) contain only the taint source with no
#       sink call; single-file analysis cannot detect the pattern there.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE195"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"

> "$RESULTS"

echo "========================================"
echo " SCS007 — SmellDetect Benchmark"
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

echo "--- Detector 1: signed_malloc (malloc_size) ---"
run_case "bad_malloc_size_01"    "tier1" "bad"  "$TESTSUITE/malloc_size/bad_malloc_size_01.c"
run_case "good_malloc_size_01"   "tier1" "good" "$TESTSUITE/malloc_size/good_malloc_size_01.c"
run_case "smell_malloc_size_01"  "tier1" "bad"  "$TESTSUITE/malloc_size/smell_malloc_size_01.c"
echo

echo "--- Detector 2: signed_memcpy (memcpy_count) ---"
run_case "bad_memcpy_count_01"    "tier1" "bad"  "$TESTSUITE/memcpy_count/bad_memcpy_count_01.c"
run_case "good_memcpy_count_01"   "tier1" "good" "$TESTSUITE/memcpy_count/good_memcpy_count_01.c"
run_case "smell_memcpy_count_01"  "tier1" "bad"  "$TESTSUITE/memcpy_count/smell_memcpy_count_01.c"
echo

echo "--- Detector 3: signed_strncpy (strncpy_count) ---"
run_case "bad_strncpy_count_01"    "tier1" "bad"  "$TESTSUITE/strncpy_count/bad_strncpy_count_01.c"
run_case "good_strncpy_count_01"   "tier1" "good" "$TESTSUITE/strncpy_count/good_strncpy_count_01.c"
run_case "smell_strncpy_count_01"  "tier1" "bad"  "$TESTSUITE/strncpy_count/smell_strncpy_count_01.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- Detector 1: signed_malloc (interprocedural sink-side) ---"
run_case "bad_signed_malloc_22b"   "tier2" "bad"  "$TESTSUITE/interprocedural/bad_signed_malloc_22b.c"
run_case "good_signed_malloc_22b"  "tier2" "good" "$TESTSUITE/interprocedural/good_signed_malloc_22b.c"
echo

echo "--- Detector 1: signed_malloc (C++ class variant) ---"
run_case "bad_signed_malloc_84"   "tier2" "bad"  "$TESTSUITE/cpp_class/bad_signed_malloc_84.cpp"
run_case "good_signed_malloc_84"  "tier2" "good" "$TESTSUITE/cpp_class/good_signed_malloc_84.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo "    (22a files contain only the taint source — no sink call present;"
echo "     single-file analysis cannot detect the pattern)"
echo

run_case "bad_signed_malloc_22a"   "tier3" "bad"  "$TESTSUITE/interprocedural/bad_signed_malloc_22a.c"
run_case "good_signed_malloc_22a"  "tier3" "good" "$TESTSUITE/interprocedural/good_signed_malloc_22a.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
