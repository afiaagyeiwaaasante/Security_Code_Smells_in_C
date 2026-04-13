#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-242 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether gets() was detected ([getsCalled])
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE242"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

> "$RESULTS"   # clear previous results

echo "========================================"
echo " SCS001 — cppcheck Benchmark"
echo " cppcheck version: $(cppcheck --version 2>&1)"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Helper: run cppcheck on one or more files, capture time + memory + detection
# -----------------------------------------------------------------------
run_case() {
    local TEST_NAME="$1"
    shift
    local FILES=("$@")

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/cppcheck_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/cppcheck_time_XXXXXX)

    /usr/bin/time -l cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    # cppcheck writes findings to stderr; TMPOUT has stdout (empty usually)
    # Re-run to capture stderr for detection check
    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" 2>&1 1>/dev/null || true)

    if echo "$CPPCHECK_STDERR" | grep -q 'getsCalled'; then
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
run_case "bad_gets_01"  "$TESTSUITE/gets/bad_gets_01.c"
run_case "good_gets_01" "$TESTSUITE/gets/good_gets_01.c"
run_case "bad_gets_interprocedural_62" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62a.c" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62b.c"

# --- Multi-instance: verify all occurrences are reported ---
run_case "bad_gets_multi_01" "$TESTSUITE/multi/bad_gets_multi_01.c"
run_case "bad_gets_multi_02" "$TESTSUITE/multi/bad_gets_multi_02.c"
run_case "bad_gets_mixed_01" "$TESTSUITE/multi/bad_gets_mixed_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
