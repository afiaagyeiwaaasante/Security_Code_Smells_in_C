#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-190 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Detection: integerOverflow | signedIntegerOverflow | unsignedIntegerOverflow
#            integerOverflowCast | shiftTooManyBits
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE190"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS006 — cppcheck Benchmark (all tiers)"
echo " cppcheck version : $(cppcheck --version 2>&1)"
echo " Output : $RESULTS"
echo " Date   : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    shift 3
    local FILES=("$@")

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

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
        local BASENAME
        BASENAME=$(basename "${FILES[$i]}")
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"${BASENAME}\""
    done
    FILES_JSON+="]"

    printf '{"test":"%s","tier":"%s","expected":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED  (expected: $EXPECTED)"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# =======================================================================
# TIER 1 — Smell pattern variants
# =======================================================================
echo "=== TIER 1: Smell pattern variants ==="
echo

run_case "bad_char_add_01"           "tier1" "bad"  "$TESTSUITE/add/bad_char_add_01.c"
run_case "good_char_add_01"          "tier1" "good" "$TESTSUITE/add/good_char_add_01.c"
run_case "smell_char_add_01"         "tier1" "bad"  "$TESTSUITE/add/smell_char_add_01.c"
run_case "bad_unsigned_int_add_01"   "tier1" "bad"  "$TESTSUITE/add/bad_unsigned_int_add_01.c"
run_case "good_unsigned_int_add_01"  "tier1" "good" "$TESTSUITE/add/good_unsigned_int_add_01.c"

run_case "bad_int_multiply_01"   "tier1" "bad"  "$TESTSUITE/multiply/bad_int_multiply_01.c"
run_case "good_int_multiply_01"  "tier1" "good" "$TESTSUITE/multiply/good_int_multiply_01.c"
run_case "smell_int_multiply_01" "tier1" "bad"  "$TESTSUITE/multiply/smell_int_multiply_01.c"

run_case "bad_int64_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_int64_square_01.c"
run_case "good_int64_square_01"   "tier1" "good" "$TESTSUITE/square/good_int64_square_01.c"
run_case "smell_int64_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_int64_square_01.c"
run_case "bad_short_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_short_square_01.c"
run_case "good_short_square_01"   "tier1" "good" "$TESTSUITE/square/good_short_square_01.c"
run_case "smell_short_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_short_square_01.c"

run_case "bad_int_postinc_01"    "tier1" "bad"  "$TESTSUITE/postinc/bad_int_postinc_01.c"
run_case "good_int_postinc_01"   "tier1" "good" "$TESTSUITE/postinc/good_int_postinc_01.c"
run_case "smell_int_postinc_01"  "tier1" "bad"  "$TESTSUITE/postinc/smell_int_postinc_01.c"

run_case "bad_int_preinc_01"    "tier1" "bad"  "$TESTSUITE/preinc/bad_int_preinc_01.c"
run_case "good_int_preinc_01"   "tier1" "good" "$TESTSUITE/preinc/good_int_preinc_01.c"
run_case "smell_int_preinc_01"  "tier1" "bad"  "$TESTSUITE/preinc/smell_int_preinc_01.c"

# =======================================================================
# TIER 2 — Context variants (C++ class patterns)
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_int_multiply_81"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ref/bad_int_multiply_81.cpp"
run_case "good_int_multiply_81"  "tier2" "good" "$TESTSUITE/cpp_virtual_ref/good_int_multiply_81.cpp"
run_case "bad_int_multiply_82"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ptr/bad_int_multiply_82.cpp"
run_case "good_int_multiply_82"  "tier2" "good" "$TESTSUITE/cpp_virtual_ptr/good_int_multiply_82.cpp"
run_case "bad_int_multiply_83"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_stack/bad_int_multiply_83.cpp"
run_case "good_int_multiply_83"  "tier2" "good" "$TESTSUITE/cpp_ctor_stack/good_int_multiply_83.cpp"
run_case "bad_int_multiply_84"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_heap/bad_int_multiply_84.cpp"
run_case "good_int_multiply_84"  "tier2" "good" "$TESTSUITE/cpp_ctor_heap/good_int_multiply_84.cpp"

# =======================================================================
# TIER 3 — Interprocedural multi-file cases
# =======================================================================
echo "=== TIER 3: Interprocedural multi-file cases ==="
echo

run_case "bad_int_add_22"       "tier3" "bad"  \
    "$TESTSUITE/interprocedural/bad_int_add_22a.c" \
    "$TESTSUITE/interprocedural/bad_int_add_22b.c"
run_case "good_int_add_22"      "tier3" "good" \
    "$TESTSUITE/interprocedural/good_int_add_22a.c" \
    "$TESTSUITE/interprocedural/good_int_add_22b.c"
run_case "bad_int_multiply_22"  "tier3" "bad"  \
    "$TESTSUITE/interprocedural/bad_int_multiply_22a.c" \
    "$TESTSUITE/interprocedural/bad_int_multiply_22b.c"
run_case "good_int_multiply_22" "tier3" "good" \
    "$TESTSUITE/interprocedural/good_int_multiply_22a.c" \
    "$TESTSUITE/interprocedural/good_int_multiply_22b.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
