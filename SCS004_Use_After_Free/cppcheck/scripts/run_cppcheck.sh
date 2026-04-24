#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-416 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Detection: deallocuse | deallocret | operatorEqToSelf
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE416"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS004 — cppcheck Benchmark (all tiers)"
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
    if echo "$CPPCHECK_STDERR" | grep -qE 'deallocuse|deallocret|operatorEqToSelf'; then
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

run_case "bad_use_after_free_char_01"    "tier1" "bad"  "$TESTSUITE/char/bad_use_after_free_char_01.c"
run_case "good_use_after_free_char_01"   "tier1" "good" "$TESTSUITE/char/good_use_after_free_char_01.c"
run_case "bad_use_after_free_int_01"     "tier1" "bad"  "$TESTSUITE/int/bad_use_after_free_int_01.c"
run_case "good_use_after_free_int_01"    "tier1" "good" "$TESTSUITE/int/good_use_after_free_int_01.c"
run_case "bad_use_after_free_int64_01"   "tier1" "bad"  "$TESTSUITE/int64/bad_use_after_free_int64_01.c"
run_case "good_use_after_free_int64_01"  "tier1" "good" "$TESTSUITE/int64/good_use_after_free_int64_01.c"
run_case "bad_use_after_free_long_01"    "tier1" "bad"  "$TESTSUITE/long/bad_use_after_free_long_01.c"
run_case "good_use_after_free_long_01"   "tier1" "good" "$TESTSUITE/long/good_use_after_free_long_01.c"

run_case "bad_double_free_01"            "tier1" "bad"  "$TESTSUITE/char/bad_double_free_01.c"
run_case "good_double_free_01"           "tier1" "good" "$TESTSUITE/char/good_double_free_01.c"

run_case "bad_delete_array_char_01"      "tier1" "bad"  "$TESTSUITE/delete_array_char/bad_delete_array_char_01.cpp"
run_case "good_delete_array_char_01"     "tier1" "good" "$TESTSUITE/delete_array_char/good_delete_array_char_01.cpp"
run_case "bad_delete_array_int64_01"     "tier1" "bad"  "$TESTSUITE/delete_array_int64_t/bad_delete_array_int64_01.cpp"
run_case "good_delete_array_int64_01"    "tier1" "good" "$TESTSUITE/delete_array_int64_t/good_delete_array_int64_01.cpp"
run_case "bad_delete_array_long_01"      "tier1" "bad"  "$TESTSUITE/delete_array_long/bad_delete_array_long_01.cpp"
run_case "good_delete_array_long_01"     "tier1" "good" "$TESTSUITE/delete_array_long/good_delete_array_long_01.cpp"
run_case "bad_delete_array_wchar_01"     "tier1" "bad"  "$TESTSUITE/delete_array_wchar_t/bad_delete_array_wchar_01.cpp"
run_case "good_delete_array_wchar_01"    "tier1" "good" "$TESTSUITE/delete_array_wchar_t/good_delete_array_wchar_01.cpp"

run_case "bad_return_freed_ptr_01"       "tier1" "bad"  "$TESTSUITE/freed_pointer/bad_return_freed_ptr_01.c"
run_case "good_return_freed_ptr_01"      "tier1" "good" "$TESTSUITE/freed_pointer/good_return_freed_ptr_01.c"

run_case "bad_new_delete_char_01"        "tier1" "bad"  "$TESTSUITE/new_delete_char/bad_new_delete_char_01.cpp"
run_case "good_new_delete_char_01"       "tier1" "good" "$TESTSUITE/new_delete_char/good_new_delete_char_01.cpp"
run_case "bad_new_delete_int_01"         "tier1" "bad"  "$TESTSUITE/new_delete_int/bad_new_delete_int_01.cpp"
run_case "good_new_delete_int_01"        "tier1" "good" "$TESTSUITE/new_delete_int/good_new_delete_int_01.cpp"
run_case "bad_new_delete_int64_01"       "tier1" "bad"  "$TESTSUITE/new_delete_int64_t/bad_new_delete_int64_01.cpp"
run_case "good_new_delete_int64_01"      "tier1" "good" "$TESTSUITE/new_delete_int64_t/good_new_delete_int64_01.cpp"
run_case "bad_new_delete_long_01"        "tier1" "bad"  "$TESTSUITE/new_delete_long/bad_new_delete_long_01.cpp"
run_case "good_new_delete_long_01"       "tier1" "good" "$TESTSUITE/new_delete_long/good_new_delete_long_01.cpp"
run_case "bad_new_delete_wchar_01"       "tier1" "bad"  "$TESTSUITE/new_delete_wchar_t/bad_new_delete_wchar_01.cpp"
run_case "good_new_delete_wchar_01"      "tier1" "good" "$TESTSUITE/new_delete_wchar_t/good_new_delete_wchar_01.cpp"

run_case "bad_operator_equals_01"        "tier1" "bad"  "$TESTSUITE/operator_equals/bad_operator_equals_01.cpp"
run_case "good_operator_equals_01"       "tier1" "good" "$TESTSUITE/operator_equals/good_operator_equals_01.cpp"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_use_after_free_struct_01"  "tier2" "bad"  "$TESTSUITE/struct/bad_use_after_free_struct_01.c"
run_case "good_use_after_free_struct_01" "tier2" "good" "$TESTSUITE/struct/good_use_after_free_struct_01.c"

run_case "bad_delete_array_struct_01"    "tier2" "bad"  "$TESTSUITE/delete_array_struct/bad_delete_array_struct_01.cpp"
run_case "good_delete_array_struct_01"   "tier2" "good" "$TESTSUITE/delete_array_struct/good_delete_array_struct_01.cpp"

run_case "bad_new_delete_struct_01"      "tier2" "bad"  "$TESTSUITE/new_delete_struct/bad_new_delete_struct_01.cpp"
run_case "good_new_delete_struct_01"     "tier2" "good" "$TESTSUITE/new_delete_struct/good_new_delete_struct_01.cpp"
run_case "bad_new_delete_class_01"       "tier2" "bad"  "$TESTSUITE/new_delete_class/bad_new_delete_class_01.cpp"
run_case "good_new_delete_class_01"      "tier2" "good" "$TESTSUITE/new_delete_class/good_new_delete_class_01.cpp"

run_case "bad_interprocedural_uaf_long_22" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22a.c" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22b.c"
run_case "bad_interprocedural_delete_array_char_62" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62b.cpp"
run_case "bad_interprocedural_new_delete_char_62" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62b.cpp"
run_case "bad_interprocedural_new_delete_class_62" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62b.cpp"
run_case "bad_interprocedural_uaf_struct_62" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62a.c" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62b.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
