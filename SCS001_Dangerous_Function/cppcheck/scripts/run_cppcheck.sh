#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on every SCS001 test case across all three tiers and records:
#   - wall-clock time, peak RSS, and detection result per case
#
# Detection mapping:
#   gets()   -> cppcheck message contains "getsCalled"
#   strcpy() -> cppcheck message contains "strcpyCalled" or "bufferOverflow"
#   strcat() -> cppcheck message contains "strcatCalled" or "bufferOverflow"
#   sprintf()-> cppcheck message contains "sprintfOverlap" or "bufferOverflow"
#                or "obsoleteFunction" (varies by cppcheck version)
#   scanf()  -> cppcheck message contains "invalidscanf" or "bufferOverflow"
#
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE242"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================================"
echo " SCS001 — cppcheck Benchmark (all tiers)"
echo " cppcheck version : $(cppcheck --version 2>&1)"
echo " Output : $RESULTS"
echo " Date   : $(date)"
echo "========================================================"
echo

# -----------------------------------------------------------------------
# Helper
# Arguments: TEST_NAME  TIER  EXPECTED  DETECT_PATTERN  FILE [FILE ...]
#   DETECT_PATTERN: grep-E pattern matched against cppcheck stderr output
# -----------------------------------------------------------------------
run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local DETECT_PATTERN="$4"
    shift 4
    local FILES=("$@")

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/cppcheck_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/cppcheck_time_XXXXXX)

    /usr/bin/time -l cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" 2>/dev/null | awk '{print $1}' || echo "0.000")
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" 2>/dev/null | awk '{print $1}' || echo "0")
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    # Re-run to capture stderr for detection check (time -l only logs to timefile)
    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" 2>&1 1>/dev/null || true)

    local DETECTED="false"
    if echo "$CPPCHECK_STDERR" | grep -qE "$DETECT_PATTERN"; then
        DETECTED="true"
    fi

    # Build files JSON array
    local FILES_JSON="["
    for i in "${!FILES[@]}"; do
        local BASENAME; BASENAME=$(basename "${FILES[$i]}")
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
# TIER 1 — Smell function variants
# =======================================================================
echo "=== TIER 1: Smell function variants ==="
echo

run_case "bad_gets_01"     "tier1" "bad"  "getsCalled"                   "$TESTSUITE/gets/bad_gets_01.c"
run_case "good_gets_01"    "tier1" "good" "getsCalled"                   "$TESTSUITE/gets/good_gets_01.c"

run_case "bad_strcpy_01"   "tier1" "bad"  "strcpyCalled|bufferOverflow"  "$TESTSUITE/strcpy/bad_strcpy_01.c"
run_case "good_strcpy_01"  "tier1" "good" "strcpyCalled|bufferOverflow"  "$TESTSUITE/strcpy/good_strcpy_01.c"

run_case "bad_strcat_01"   "tier1" "bad"  "strcatCalled|bufferOverflow"  "$TESTSUITE/strcat/bad_strcat_01.c"
run_case "good_strcat_01"  "tier1" "good" "strcatCalled|bufferOverflow"  "$TESTSUITE/strcat/good_strcat_01.c"

run_case "bad_sprintf_01"  "tier1" "bad"  "sprintfOverlap|obsoleteFunction|bufferOverflow" \
    "$TESTSUITE/sprintf/bad_sprintf_01.c"
run_case "good_sprintf_01" "tier1" "good" "sprintfOverlap|obsoleteFunction|bufferOverflow" \
    "$TESTSUITE/sprintf/good_sprintf_01.c"

run_case "bad_scanf_01"    "tier1" "bad"  "invalidscanf|bufferOverflow"  "$TESTSUITE/scanf/bad_scanf_01.c"
run_case "good_scanf_01"   "tier1" "good" "invalidscanf|bufferOverflow"  "$TESTSUITE/scanf/good_scanf_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_gets_interprocedural_62" "tier2" "bad" "getsCalled" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62a.c" \
    "$TESTSUITE/interprocedural/bad_gets_interprocedural_62b.c"

run_case "bad_gets_multi_01" "tier2" "bad" "getsCalled" "$TESTSUITE/multi/bad_gets_multi_01.c"
run_case "bad_gets_multi_02" "tier2" "bad" "getsCalled" "$TESTSUITE/multi/bad_gets_multi_02.c"
run_case "bad_gets_mixed_01" "tier2" "bad" "getsCalled" "$TESTSUITE/multi/bad_gets_mixed_01.c"

# =======================================================================
# TIER 3 — Known limitation cases
# =======================================================================
echo "=== TIER 3: Known limitation cases ==="
echo

run_case "bad_gets_macro_01" "tier3" "bad" "getsCalled" \
    "$TESTSUITE/get_macro/bad_gets_macros_01.c"

run_case "bad_gets_fnptr_01" "tier3" "bad" "getsCalled" \
    "$TESTSUITE/get_macro/bad_gets_fnptr_01.c"

echo "========================================================"
echo " Results saved to : $RESULTS"
echo "========================================================"