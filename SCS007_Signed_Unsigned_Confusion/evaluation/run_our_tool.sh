#!/usr/bin/env bash
# evaluation/run_our_tool.sh
# Runs our SCS007 tool on representative CWE-195 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/our_tool_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE195"
RESULTS="$SCRIPT_DIR/our_tool_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS007 — Our Tool Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local FILE="$2"

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/our_tool_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/our_tool_time_XXXXXX)

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

# Group 1 — malloc_size
run_case "bad_malloc_size_01"   "$TESTSUITE/malloc_size/bad_malloc_size_01.c"
run_case "good_malloc_size_01"  "$TESTSUITE/malloc_size/good_malloc_size_01.c"

# Group 2 — memcpy_count
run_case "bad_memcpy_count_01"   "$TESTSUITE/memcpy_count/bad_memcpy_count_01.c"
run_case "good_memcpy_count_01"  "$TESTSUITE/memcpy_count/good_memcpy_count_01.c"

# Group 3 — strncpy_count
run_case "bad_strncpy_count_01"   "$TESTSUITE/strncpy_count/bad_strncpy_count_01.c"
run_case "good_strncpy_count_01"  "$TESTSUITE/strncpy_count/good_strncpy_count_01.c"

# Group 4 — interprocedural (sink file)
run_case "bad_signed_malloc_22b"   "$TESTSUITE/interprocedural/bad_signed_malloc_22b.c"
run_case "good_signed_malloc_22b"  "$TESTSUITE/interprocedural/good_signed_malloc_22b.c"

# Group 5 — cpp_class (flow 84)
run_case "bad_signed_malloc_84"   "$TESTSUITE/cpp_class/bad_signed_malloc_84.cpp"
run_case "good_signed_malloc_84"  "$TESTSUITE/cpp_class/good_signed_malloc_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
