#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-134 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Detection: invalidPrintfArgType | wrongPrintfScanfArgNum | formatStringIsVararg | invalidScanfArgType
#   Note: cppcheck detects format-string issues when the argument is a variable
#   rather than a string literal; --inconclusive enables additional heuristics.
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE134"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS008 — cppcheck Benchmark (all tiers)"
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
        'invalidPrintfArgType|wrongPrintfScanfArgNum|formatStringIsVararg|invalidScanfArgType'; then
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

run_case "bad_printf_direct_01"  "tier1" "bad"  "$TESTSUITE/printf_direct/bad_printf_direct_01.c"
run_case "good_printf_direct_01" "tier1" "good" "$TESTSUITE/printf_direct/good_printf_direct_01.c"

run_case "bad_fprintf_direct_01"  "tier1" "bad"  "$TESTSUITE/fprintf_direct/bad_fprintf_direct_01.c"
run_case "good_fprintf_direct_01" "tier1" "good" "$TESTSUITE/fprintf_direct/good_fprintf_direct_01.c"

run_case "bad_env_format_01"  "tier1" "bad"  "$TESTSUITE/env_format/bad_env_format_01.c"
run_case "good_env_format_01" "tier1" "good" "$TESTSUITE/env_format/good_env_format_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_printf_interprocedural_22b"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_printf_interprocedural_22b.c"
run_case "good_printf_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_printf_interprocedural_22b.c"

run_case "bad_printf_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_printf_class_84.cpp"
run_case "good_printf_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_printf_class_84.cpp"

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural source-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo

run_case "bad_printf_interprocedural_22a"  "tier3" "bad"  "$TESTSUITE/interprocedural/bad_printf_interprocedural_22a.c"
run_case "good_printf_interprocedural_22a" "tier3" "good" "$TESTSUITE/interprocedural/good_printf_interprocedural_22a.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
