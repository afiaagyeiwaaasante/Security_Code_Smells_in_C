#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on representative CWE-476 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a null pointer smell was detected
# Detection: any of nullPointer | nullPointerOutOfMemory | bitwiseOnBoolean
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS003 — cppcheck Benchmark"
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

    /usr/bin/time -l cppcheck --enable=all --suppress=missingInclude \
        "${FILES[@]}" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingInclude \
        "${FILES[@]}" 2>&1 1>/dev/null || true)

    local DETECTED="false"
    if echo "$CPPCHECK_STDERR" | grep -qE 'nullPointer|nullPointerOutOfMemory|bitwiseOnBoolean|uninitvar'; then
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

# Detector 1 — binary_if
run_case "bad_binary_if_01"   "$TESTSUITE/binary_if/bad_binary_if_01.c"
run_case "good_binary_if_01"  "$TESTSUITE/binary_if/good_binary_if_01.c"

# Detector 3 — null_deref
run_case "bad_null_deref_01"  "$TESTSUITE/deref_no_check/bad_null_deref_01.c"
run_case "good_guarded_01"    "$TESTSUITE/deref_no_check/good_guarded_01.c"

# Detector 2 — interprocedural (single-file)
run_case "bad_interprocedural_01"  "$TESTSUITE/interprocedural/bad_interprocedural_01.c"
run_case "good_interprocedural_01" "$TESTSUITE/interprocedural/good_interprocedural_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
