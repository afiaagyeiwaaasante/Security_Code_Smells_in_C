#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS004 tool on each CWE-416 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE416"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"
SMELL_REPORT_MULTI="$SRC_DIR/smell_report_multi.sh"

> "$RESULTS"

echo "========================================"
echo " SCS004 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local MODE="$4"          # single | multi
    shift 4
    local FILES=("$@")

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

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

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local FINDING_COUNT DETECTED
    if [ "$MODE" = "single" ]; then
        FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
        FINDING_COUNT=${FINDING_COUNT:-0}
        if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi
    else
        local ERR_COUNT WARN_COUNT
        ERR_COUNT=$(grep -oE '[0-9]+ error\(s\) detected' "$TMPOUT" 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        WARN_COUNT=$(grep -oE '[0-9]+ warning\(s\) detected' "$TMPOUT" 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        FINDING_COUNT=$(( ERR_COUNT + WARN_COUNT ))
        if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi
    fi

    local FILES_JSON="["
    for i in "${!FILES[@]}"; do
        local BASENAME
        BASENAME=$(basename "${FILES[$i]}")
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"${BASENAME}\""
    done
    FILES_JSON+="]"

    printf '{"test":"%s","tier":"%s","expected":"%s","files":%s,"detected":%s,"finding_count":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$FILES_JSON" "$DETECTED" "$FINDING_COUNT" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected      : $DETECTED"
    echo "    finding count : $FINDING_COUNT"
    echo "    wall time     : ${WALL_TIME}s"
    echo "    peak RSS      : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# -----------------------------------------------------------------------
echo "=== TIER 1: Smell pattern variants ==="
echo

echo "--- Detector 1: use_after_free (malloc/free, scalar types) ---"
run_case "bad_use_after_free_char_01"    "tier1" "bad"  single "$TESTSUITE/char/bad_use_after_free_char_01.c"
run_case "good_use_after_free_char_01"   "tier1" "good" single "$TESTSUITE/char/good_use_after_free_char_01.c"
run_case "bad_use_after_free_int_01"     "tier1" "bad"  single "$TESTSUITE/int/bad_use_after_free_int_01.c"
run_case "good_use_after_free_int_01"    "tier1" "good" single "$TESTSUITE/int/good_use_after_free_int_01.c"
run_case "bad_use_after_free_int64_01"   "tier1" "bad"  single "$TESTSUITE/int64/bad_use_after_free_int64_01.c"
run_case "good_use_after_free_int64_01"  "tier1" "good" single "$TESTSUITE/int64/good_use_after_free_int64_01.c"
run_case "bad_use_after_free_long_01"    "tier1" "bad"  single "$TESTSUITE/long/bad_use_after_free_long_01.c"
run_case "good_use_after_free_long_01"   "tier1" "good" single "$TESTSUITE/long/good_use_after_free_long_01.c"
echo

echo "--- Detector 2: double_free ---"
run_case "bad_double_free_01"            "tier1" "bad"  single "$TESTSUITE/char/bad_double_free_01.c"
run_case "good_double_free_01"           "tier1" "good" single "$TESTSUITE/char/good_double_free_01.c"
echo

echo "--- Detector 4: delete_array_uaf (scalar types) ---"
run_case "bad_delete_array_char_01"      "tier1" "bad"  single "$TESTSUITE/delete_array_char/bad_delete_array_char_01.cpp"
run_case "good_delete_array_char_01"     "tier1" "good" single "$TESTSUITE/delete_array_char/good_delete_array_char_01.cpp"
run_case "bad_delete_array_int64_01"     "tier1" "bad"  single "$TESTSUITE/delete_array_int64_t/bad_delete_array_int64_01.cpp"
run_case "good_delete_array_int64_01"    "tier1" "good" single "$TESTSUITE/delete_array_int64_t/good_delete_array_int64_01.cpp"
run_case "bad_delete_array_long_01"      "tier1" "bad"  single "$TESTSUITE/delete_array_long/bad_delete_array_long_01.cpp"
run_case "good_delete_array_long_01"     "tier1" "good" single "$TESTSUITE/delete_array_long/good_delete_array_long_01.cpp"
run_case "bad_delete_array_wchar_01"     "tier1" "bad"  single "$TESTSUITE/delete_array_wchar_t/bad_delete_array_wchar_01.cpp"
run_case "good_delete_array_wchar_01"    "tier1" "good" single "$TESTSUITE/delete_array_wchar_t/good_delete_array_wchar_01.cpp"
echo

echo "--- Detector 5: return_freed_ptr ---"
run_case "bad_return_freed_ptr_01"       "tier1" "bad"  single "$TESTSUITE/freed_pointer/bad_return_freed_ptr_01.c"
run_case "good_return_freed_ptr_01"      "tier1" "good" single "$TESTSUITE/freed_pointer/good_return_freed_ptr_01.c"
echo

echo "--- Detector 6: new_delete_uaf (scalar types) ---"
run_case "bad_new_delete_char_01"        "tier1" "bad"  single "$TESTSUITE/new_delete_char/bad_new_delete_char_01.cpp"
run_case "good_new_delete_char_01"       "tier1" "good" single "$TESTSUITE/new_delete_char/good_new_delete_char_01.cpp"
run_case "bad_new_delete_int_01"         "tier1" "bad"  single "$TESTSUITE/new_delete_int/bad_new_delete_int_01.cpp"
run_case "good_new_delete_int_01"        "tier1" "good" single "$TESTSUITE/new_delete_int/good_new_delete_int_01.cpp"
run_case "bad_new_delete_int64_01"       "tier1" "bad"  single "$TESTSUITE/new_delete_int64_t/bad_new_delete_int64_01.cpp"
run_case "good_new_delete_int64_01"      "tier1" "good" single "$TESTSUITE/new_delete_int64_t/good_new_delete_int64_01.cpp"
run_case "bad_new_delete_long_01"        "tier1" "bad"  single "$TESTSUITE/new_delete_long/bad_new_delete_long_01.cpp"
run_case "good_new_delete_long_01"       "tier1" "good" single "$TESTSUITE/new_delete_long/good_new_delete_long_01.cpp"
run_case "bad_new_delete_wchar_01"       "tier1" "bad"  single "$TESTSUITE/new_delete_wchar_t/bad_new_delete_wchar_01.cpp"
run_case "good_new_delete_wchar_01"      "tier1" "good" single "$TESTSUITE/new_delete_wchar_t/good_new_delete_wchar_01.cpp"
echo

echo "--- Detector 7: operator_equals_uaf ---"
run_case "bad_operator_equals_01"        "tier1" "bad"  single "$TESTSUITE/operator_equals/bad_operator_equals_01.cpp"
run_case "good_operator_equals_01"       "tier1" "good" single "$TESTSUITE/operator_equals/good_operator_equals_01.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- Detector 1: use_after_free (struct) ---"
run_case "bad_use_after_free_struct_01"  "tier2" "bad"  single "$TESTSUITE/struct/bad_use_after_free_struct_01.c"
run_case "good_use_after_free_struct_01" "tier2" "good" single "$TESTSUITE/struct/good_use_after_free_struct_01.c"
echo

echo "--- Detector 4: delete_array_uaf (struct) ---"
run_case "bad_delete_array_struct_01"    "tier2" "bad"  single "$TESTSUITE/delete_array_struct/bad_delete_array_struct_01.cpp"
run_case "good_delete_array_struct_01"   "tier2" "good" single "$TESTSUITE/delete_array_struct/good_delete_array_struct_01.cpp"
echo

echo "--- Detector 6: new_delete_uaf (struct, class) ---"
run_case "bad_new_delete_struct_01"      "tier2" "bad"  single "$TESTSUITE/new_delete_struct/bad_new_delete_struct_01.cpp"
run_case "good_new_delete_struct_01"     "tier2" "good" single "$TESTSUITE/new_delete_struct/good_new_delete_struct_01.cpp"
run_case "bad_new_delete_class_01"       "tier2" "bad"  single "$TESTSUITE/new_delete_class/bad_new_delete_class_01.cpp"
run_case "good_new_delete_class_01"      "tier2" "good" single "$TESTSUITE/new_delete_class/good_new_delete_class_01.cpp"
echo

echo "--- Detector 3: interprocedural_uaf (multi-file) ---"
run_case "bad_interprocedural_uaf_long_22" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22a.c" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22b.c"
run_case "bad_interprocedural_delete_array_char_62" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62b.cpp"
run_case "bad_interprocedural_new_delete_char_62" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62b.cpp"
run_case "bad_interprocedural_new_delete_class_62" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62a.cpp" \
    "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62b.cpp"
run_case "bad_interprocedural_uaf_struct_62" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62a.c" \
    "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62b.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
