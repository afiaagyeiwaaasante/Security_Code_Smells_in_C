#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on representative CWE-401 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a memory-leak smell was detected
# Detection: memleak | memleakOnRealloc | resourceLeak | autovarInvalidDeallocation
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE401"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS005 — cppcheck Benchmark"
echo " cppcheck version: $(cppcheck --version 2>&1)"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

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

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" 2>&1 1>/dev/null || true)

    local DETECTED="false"
    if echo "$CPPCHECK_STDERR" | grep -qE 'memleak|memleakOnRealloc|resourceLeak|autovarInvalidDeallocation'; then
        DETECTED="true"
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

# Detector 1 — no_free_on_exit
run_case "bad_malloc_no_free_01"    "$TESTSUITE/int/bad_malloc_no_free_01.c"
run_case "good_malloc_with_free_01" "$TESTSUITE/int/good_malloc_with_free_01.c"

# Detector 1 — early_return variant
run_case "bad_early_return_01"  "$TESTSUITE/early_return/bad_early_return_01.c"
run_case "good_early_return_01" "$TESTSUITE/early_return/good_early_return_01.c"

# Detector 2 — overwrite_leak
run_case "bad_overwrite_01"  "$TESTSUITE/overwrite/bad_overwrite_01.c"
run_case "good_overwrite_01" "$TESTSUITE/overwrite/good_overwrite_01.c"

# Detector 3 — new_no_delete
run_case "bad_new_no_delete_01"  "$TESTSUITE/new_delete/bad_new_no_delete_01.cpp"
run_case "good_new_delete_01"    "$TESTSUITE/new_delete/good_new_delete_01.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
