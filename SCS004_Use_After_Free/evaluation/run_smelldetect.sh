#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS004 tool on representative CWE-416 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE416"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS004 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local FILE="$2"

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    /usr/bin/time -l bash "$SRC_DIR/smell_report.sh" "$FILE" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q '"severity":' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","files":["%s"],"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$(basename "$FILE")" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# Detector 1 — use_after_free (malloc/free)
run_case "bad_use_after_free_int_01"  "$TESTSUITE/int/bad_use_after_free_int_01.c"
run_case "good_use_after_free_int_01" "$TESTSUITE/int/good_use_after_free_int_01.c"

# Detector 4 — new_delete_uaf (C++ new/delete)
run_case "bad_new_delete_int_01"  "$TESTSUITE/new_delete_int/bad_new_delete_int_01.cpp"
run_case "good_new_delete_int_01" "$TESTSUITE/new_delete_int/good_new_delete_int_01.cpp"

# Detector 6 — return_freed_ptr
run_case "bad_return_freed_ptr_01"  "$TESTSUITE/freed_pointer/bad_return_freed_ptr_01.c"
run_case "good_return_freed_ptr_01" "$TESTSUITE/freed_pointer/good_return_freed_ptr_01.c"

# Detector 7 — operator_equals_uaf
run_case "bad_operator_equals_01"  "$TESTSUITE/operator_equals/bad_operator_equals_01.cpp"
run_case "good_operator_equals_01" "$TESTSUITE/operator_equals/good_operator_equals_01.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
