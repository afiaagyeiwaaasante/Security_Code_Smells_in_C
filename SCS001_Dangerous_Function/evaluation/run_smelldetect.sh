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

    local FINDING_COUNT
    FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
    FINDING_COUNT=${FINDING_COUNT:-0}

    if [ "$FINDING_COUNT" -gt 0 ]; then
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

    printf '{"test":"%s","files":%s,"detected":%s,"finding_count":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$FILES_JSON" "$DETECTED" "$FINDING_COUNT" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected      : $DETECTED"
    echo "    finding count : $FINDING_COUNT"
    echo "    wall time     : ${WALL_TIME}s"
    echo "    peak RSS      : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# -----------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------

# --- Baseline ---
run_case "bad_gets_01"   single "$TESTSUITE/gets/bad_gets_01.c"
run_case "good_gets_01"  single "$TESTSUITE/gets/good_gets_01.c"

# --- Interprocedural ---
run_case "bad_gets_interprocedural_62" multi \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62a.c" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62b.c"

# --- Multi-instance: verify all occurrences are reported ---
# bad_gets_multi_01: 3 functions each calling gets() — expect 3 findings
run_case "bad_gets_multi_01" single "$TESTSUITE/multi/bad_gets_multi_01.c"

# bad_gets_multi_02: 1 function calling gets() twice — expect 2 findings
run_case "bad_gets_multi_02" single "$TESTSUITE/multi/bad_gets_multi_02.c"

# bad_gets_mixed_01: 1 bad function (gets) + 1 good function (fgets) — expect 1 finding
run_case "bad_gets_mixed_01" single "$TESTSUITE/multi/bad_gets_mixed_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
