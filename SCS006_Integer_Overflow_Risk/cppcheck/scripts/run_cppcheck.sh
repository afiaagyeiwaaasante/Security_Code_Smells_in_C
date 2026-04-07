#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on representative CWE-190 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether an integer overflow smell was detected
# Detection keywords: integerOverflow | signedIntegerOverflow | unsignedIntegerOverflow
#                     integerOverflowCast | shiftTooManyBits | multiCondition
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE190"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

mkdir -p "$(dirname "$RESULTS")"
> "$RESULTS"

echo "========================================"
echo " SCS006 — cppcheck Benchmark"
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
    if echo "$CPPCHECK_STDERR" | grep -qE \
        'integerOverflow|signedIntegerOverflow|unsignedIntegerOverflow|integerOverflowCast|shiftTooManyBits'; then
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

# Detector 1 — unchecked_multiply
run_case "bad_int_multiply_01"   "$TESTSUITE/multiply/bad_int_multiply_01.c"
run_case "good_int_multiply_01"  "$TESTSUITE/multiply/good_int_multiply_01.c"

# Detector 2 — unchecked_add
run_case "bad_char_add_01"           "$TESTSUITE/add/bad_char_add_01.c"
run_case "good_char_add_01"          "$TESTSUITE/add/good_char_add_01.c"
run_case "bad_unsigned_int_add_01"   "$TESTSUITE/add/bad_unsigned_int_add_01.c"
run_case "good_unsigned_int_add_01"  "$TESTSUITE/add/good_unsigned_int_add_01.c"

# Square (multiply variant)
run_case "bad_int64_square_01"   "$TESTSUITE/square/bad_int64_square_01.c"
run_case "good_int64_square_01"  "$TESTSUITE/square/good_int64_square_01.c"
run_case "bad_short_square_01"   "$TESTSUITE/square/bad_short_square_01.c"
run_case "good_short_square_01"  "$TESTSUITE/square/good_short_square_01.c"

# Detector 3 — unchecked_increment (postfix)
run_case "bad_int_postinc_01"   "$TESTSUITE/postinc/bad_int_postinc_01.c"
run_case "good_int_postinc_01"  "$TESTSUITE/postinc/good_int_postinc_01.c"

# Detector 3 — unchecked_increment (prefix)
run_case "bad_int_preinc_01"    "$TESTSUITE/preinc/bad_int_preinc_01.c"
run_case "good_int_preinc_01"   "$TESTSUITE/preinc/good_int_preinc_01.c"

# C++ class variants
run_case "bad_int_multiply_81"   "$TESTSUITE/cpp_virtual_ref/bad_int_multiply_81.cpp"
run_case "good_int_multiply_81"  "$TESTSUITE/cpp_virtual_ref/good_int_multiply_81.cpp"
run_case "bad_int_multiply_82"   "$TESTSUITE/cpp_virtual_ptr/bad_int_multiply_82.cpp"
run_case "good_int_multiply_82"  "$TESTSUITE/cpp_virtual_ptr/good_int_multiply_82.cpp"
run_case "bad_int_multiply_83"   "$TESTSUITE/cpp_ctor_stack/bad_int_multiply_83.cpp"
run_case "good_int_multiply_83"  "$TESTSUITE/cpp_ctor_stack/good_int_multiply_83.cpp"
run_case "bad_int_multiply_84"   "$TESTSUITE/cpp_ctor_heap/bad_int_multiply_84.cpp"
run_case "good_int_multiply_84"  "$TESTSUITE/cpp_ctor_heap/good_int_multiply_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
