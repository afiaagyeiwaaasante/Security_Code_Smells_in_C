#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS001 tool on each CWE-242 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE242"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"
SMELL_REPORT_MULTI="$SRC_DIR/smell_report_multi.sh"

> "$RESULTS"   # clear previous results

echo "========================================"
echo " SCS001 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Helper: run tool on one or more files, capture time + memory + detection
# -----------------------------------------------------------------------
run_case() {
    local TEST_NAME="$1"
    local MODE="$2"          # single | multi
    shift 2
    local FILES=("$@")

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    if [ "$MODE" = "single" ]; then
        /usr/bin/time -l bash "$SMELL_REPORT" "${FILES[0]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    else
        /usr/bin/time -l bash "$SMELL_REPORT_MULTI" "${FILES[@]}" \
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

    # Build files JSON array
    local FILES_JSON="["
    for i in "${!FILES[@]}"; do
        local BASENAME
        BASENAME=$(basename "${FILES[$i]}")
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"${BASENAME}\""
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

# -----------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------
run_case "bad_gets_01"   single "$TESTSUITE/gets/bad_gets_01.c"
run_case "good_gets_01"  single "$TESTSUITE/gets/good_gets_01.c"
run_case "bad_gets_interprocedural_62" multi \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62a.c" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62b.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
