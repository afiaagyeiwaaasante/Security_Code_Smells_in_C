#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-259 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Detection: hardcodedCredentials | hardcodedPassword
#   Note: cppcheck checks for hard-coded passwords passed to authentication
#   API calls via its library configuration; general variable assignments
#   with credential names are typically not flagged.
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE259"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS010 — cppcheck Benchmark (all tiers)"
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
    if echo "$CPPCHECK_STDERR" | grep -qE '\[hardcodedCredentials\]|\[hardcodedPassword\]'; then
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

run_case "bad_password_var_01"  "tier1" "bad"  "$TESTSUITE/password_var/bad_password_var_01.c"
run_case "good_password_var_01" "tier1" "good" "$TESTSUITE/password_var/good_password_var_01.c"

run_case "bad_define_const_01"  "tier1" "bad"  "$TESTSUITE/define_const/bad_define_const_01.c"
run_case "good_define_const_01" "tier1" "good" "$TESTSUITE/define_const/good_define_const_01.c"

run_case "bad_strcmp_auth_01"  "tier1" "bad"  "$TESTSUITE/strcmp_auth/bad_strcmp_auth_01.c"
run_case "good_strcmp_auth_01" "tier1" "good" "$TESTSUITE/strcmp_auth/good_strcmp_auth_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_password_interprocedural_22a"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_password_interprocedural_22a.c"
run_case "good_password_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_password_interprocedural_22b.c"

run_case "bad_password_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_password_class_84.cpp"
run_case "good_password_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_password_class_84.cpp"

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural sink-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural sink-only) ==="
echo

run_case "bad_password_interprocedural_22b" "tier3" "bad" "$TESTSUITE/interprocedural/bad_password_interprocedural_22b.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
