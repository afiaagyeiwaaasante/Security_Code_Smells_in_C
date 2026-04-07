#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on representative CWE-195 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a signed-to-unsigned conversion smell was detected
#
# Detection keywords: signConversion | negativeIndex | bufferAccessOutOfBounds
#   Note: cppcheck requires value-range analysis to prove a value is negative
#   before flagging it. For runtime-determined values (e.g. from fscanf), it
#   typically cannot prove negativity and will miss all cases.
#
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE195"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

mkdir -p "$(dirname "$RESULTS")"
> "$RESULTS"

echo "========================================"
echo " SCS007 — cppcheck Benchmark"
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
        --inconclusive "${FILES[@]}" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingIncludeSystem \
        --inconclusive "${FILES[@]}" 2>&1 1>/dev/null || true)

    local DETECTED="false"
    if echo "$CPPCHECK_STDERR" | grep -qE \
        'signConversion|negativeIndex|bufferAccessOutOfBounds|argumentSize'; then
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

# Group 1 — malloc_size
run_case "bad_malloc_size_01"   "$TESTSUITE/malloc_size/bad_malloc_size_01.c"
run_case "good_malloc_size_01"  "$TESTSUITE/malloc_size/good_malloc_size_01.c"

# Group 2 — memcpy_count
run_case "bad_memcpy_count_01"   "$TESTSUITE/memcpy_count/bad_memcpy_count_01.c"
run_case "good_memcpy_count_01"  "$TESTSUITE/memcpy_count/good_memcpy_count_01.c"

# Group 3 — strncpy_count
run_case "bad_strncpy_count_01"   "$TESTSUITE/strncpy_count/bad_strncpy_count_01.c"
run_case "good_strncpy_count_01"  "$TESTSUITE/strncpy_count/good_strncpy_count_01.c"

# Group 4 — interprocedural (sink file only — source has no sink call)
run_case "bad_signed_malloc_22b"   "$TESTSUITE/interprocedural/bad_signed_malloc_22b.c"
run_case "good_signed_malloc_22b"  "$TESTSUITE/interprocedural/good_signed_malloc_22b.c"

# Group 5 — cpp_class (flow 84)
run_case "bad_signed_malloc_84"   "$TESTSUITE/cpp_class/bad_signed_malloc_84.cpp"
run_case "good_signed_malloc_84"  "$TESTSUITE/cpp_class/good_signed_malloc_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
