#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS008 tool on representative CWE-134 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE134"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS008 — SmellDetect Benchmark"
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

# Group 1 — printf_direct
run_case "bad_printf_direct_01"  "$TESTSUITE/printf_direct/bad_printf_direct_01.c"
run_case "good_printf_direct_01" "$TESTSUITE/printf_direct/good_printf_direct_01.c"

# Group 2 — fprintf_direct
run_case "bad_fprintf_direct_01"  "$TESTSUITE/fprintf_direct/bad_fprintf_direct_01.c"
run_case "good_fprintf_direct_01" "$TESTSUITE/fprintf_direct/good_fprintf_direct_01.c"

# Group 3 — env_format
run_case "bad_env_format_01"  "$TESTSUITE/env_format/bad_env_format_01.c"
run_case "good_env_format_01" "$TESTSUITE/env_format/good_env_format_01.c"

# Group 4 — interprocedural (sink file)
run_case "bad_printf_interprocedural_22b"  "$TESTSUITE/interprocedural/bad_printf_interprocedural_22b.c"
run_case "good_printf_interprocedural_22b" "$TESTSUITE/interprocedural/good_printf_interprocedural_22b.c"

# Group 5 — cpp_class (flow 84)
run_case "bad_printf_class_84"  "$TESTSUITE/cpp_class/bad_printf_class_84.cpp"
run_case "good_printf_class_84" "$TESTSUITE/cpp_class/good_printf_class_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
