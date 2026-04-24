#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-476 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Detection: any of nullPointer | nullPointerOutOfMemory | bitwiseOnBoolean | uninitvar
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS003 — cppcheck Benchmark (all tiers)"
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
    if echo "$CPPCHECK_STDERR" | grep -qE 'nullPointer|nullPointerOutOfMemory|bitwiseOnBoolean|uninitvar'; then
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

run_case "bad_binary_if_01"    "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_01.c"
run_case "bad_binary_if_flow02" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow02.c"
run_case "bad_binary_if_flow05" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow05.c"
run_case "bad_binary_if_flow11" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow11.c"
run_case "good_binary_if_01"   "tier1" "good" "$TESTSUITE/binary_if/good_binary_if_01.c"

run_case "bad_null_deref_01"   "tier1" "bad"  "$TESTSUITE/deref_no_check/bad_null_deref_01.c"
run_case "good_guarded_01"     "tier1" "good" "$TESTSUITE/deref_no_check/good_guarded_01.c"
run_case "smell_no_guard_01"   "tier1" "bad"  "$TESTSUITE/deref_no_check/smell_no_guard_01.c"

run_case "bad_char_01"         "tier1" "bad"  "$TESTSUITE/char/bad_char_01.c"
run_case "bad_char_01b"        "tier1" "bad"  "$TESTSUITE/char/bad_char_01b.c"
run_case "good_char_01"        "tier1" "good" "$TESTSUITE/char/good_char_01.c"
run_case "smell_char_01b"      "tier1" "bad"  "$TESTSUITE/char/smell_char_01b.c"
run_case "good_char_01b"       "tier1" "good" "$TESTSUITE/char/good_char_01b.c"

run_case "bad_deref_after_check_01" "tier1" "bad"  "$TESTSUITE/after_check/bad_deref_after_check_01.c"
run_case "bad_check_after_deref_01" "tier1" "bad"  "$TESTSUITE/check_after_deref/bad_check_after_deref_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_interprocedural_01"      "tier2" "bad" "$TESTSUITE/interprocedural/bad_interprocedural_01.c"
run_case "good_interprocedural_01"     "tier2" "bad" "$TESTSUITE/interprocedural/good_interprocedural_01.c"
run_case "bad_char_interprocedural_01" "tier2" "bad" "$TESTSUITE/interprocedural/bad_char_interprocedural_01.c"
run_case "bad_char_interprocedural_22" "tier2" "bad" \
    "$TESTSUITE/interprocedural/bad_char_interprocedural_22a.c" \
    "$TESTSUITE/interprocedural/bad_char_interprocedural_22b.c"

# =======================================================================
# TIER 3 — Known limitation cases
# =======================================================================
echo "=== TIER 3: Known limitation cases ==="
echo

run_case "smell_char_01"            "tier3" "bad" "$TESTSUITE/char/smell_char_01.c"
run_case "bad_struct_ptr_to_ptr_01" "tier3" "bad" "$TESTSUITE/struct/bad_struct_ptr_to_ptr_01.c"
run_case "bad_struct_copy_01"       "tier3" "bad" "$TESTSUITE/struct/bad_struct_copy_01.c"
run_case "bad_struct_union_01"      "tier3" "bad" "$TESTSUITE/struct/bad_struct_union_01.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
