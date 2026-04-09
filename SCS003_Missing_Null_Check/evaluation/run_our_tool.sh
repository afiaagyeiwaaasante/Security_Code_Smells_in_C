#!/usr/bin/env bash
# evaluation/run_our_tool.sh
# Runs our SCS003 tool on representative CWE-476 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/our_tool_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/our_tool_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS003 — Our Tool Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local MODE="$2"      # single | multi
    shift 2
    local FILES=("$@")

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/our_tool_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/our_tool_time_XXXXXX)

    if [ "$MODE" = "single" ]; then
        /usr/bin/time -l bash "$SRC_DIR/smell_report.sh" "${FILES[0]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    else
        /usr/bin/time -l bash "$SRC_DIR/smell_report_multi.sh" "${FILES[@]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    fi

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q '"severity":' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    local FILES_JSON="["
    for i in "${!FILES[@]}"; do
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"$(basename "${FILES[$i]}")\""
    done
    FILES_JSON+="]"

    printf '{"test":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# Detector 1 — binary_if
run_case "bad_binary_if_01"  single "$TESTSUITE/binary_if/bad_binary_if_01.c"
run_case "good_binary_if_01" single "$TESTSUITE/binary_if/good_binary_if_01.c"

# Detector 3 — null_deref
run_case "bad_null_deref_01" single "$TESTSUITE/deref_no_check/bad_null_deref_01.c"
run_case "good_guarded_01"   single "$TESTSUITE/deref_no_check/good_guarded_01.c"

# Detector 2 — interprocedural (single-file)
run_case "bad_interprocedural_01"  single "$TESTSUITE/interprocedural/bad_interprocedural_01.c"
run_case "good_interprocedural_01" single "$TESTSUITE/interprocedural/good_interprocedural_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
