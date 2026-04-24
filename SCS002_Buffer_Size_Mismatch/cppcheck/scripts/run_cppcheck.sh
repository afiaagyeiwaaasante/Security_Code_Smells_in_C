#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on each CWE-680 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# NOTE: cppcheck does not have a specific check for malloc(n * sizeof(T)).
#       Detection will show MISSED for most bad cases.
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE680"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS002 — cppcheck Benchmark (all tiers)"
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

    # cppcheck has no specific check for malloc(n * sizeof) integer overflow.
    # Check for integerOverflow or bufferAccessOutOfBounds as closest matches.
    local CPPCHECK_STDERR
    CPPCHECK_STDERR=$(cppcheck --enable=all --suppress=missingIncludeSystem \
        "${FILES[@]}" 2>&1 1>/dev/null || true)

    local DETECTED="false"
    if echo "$CPPCHECK_STDERR" | grep -qE 'integerOverflow|bufferAccessOutOfBounds|bufferOverflow'; then
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

run_case "bad_malloc_01"          "tier1" "bad"  "$TESTSUITE/malloc/bad_malloc_01.c"
run_case "good_malloc_01"         "tier1" "good" "$TESTSUITE/malloc/good_malloc_01.c"
run_case "good_malloc_01_guarded" "tier1" "good" "$TESTSUITE/malloc/good_malloc_01_guarded.c"

run_case "bad_malloc_fixed_01"          "tier1" "bad"  "$TESTSUITE/malloc/bad_malloc_fixed_01.c"
run_case "good_malloc_fixed_01"         "tier1" "good" "$TESTSUITE/malloc/good_malloc_fixed_01.c"
run_case "good_malloc_fixed_01_guarded" "tier1" "good" "$TESTSUITE/malloc/good_malloc_fixed_01_guarded.c"

run_case "bad_malloc_fgets_01"          "tier1" "bad"  "$TESTSUITE/malloc/bad_malloc_fgets_01.c"
run_case "good_malloc_fgets_01"         "tier1" "good" "$TESTSUITE/malloc/good_malloc_fgets_01.c"
run_case "good_malloc_fgets_01_guarded" "tier1" "good" "$TESTSUITE/malloc/good_malloc_fgets_01_guarded.c"

run_case "bad_malloc_rand_01"          "tier1" "bad"  "$TESTSUITE/malloc/bad_malloc_rand_01.c"
run_case "good_malloc_rand_01"         "tier1" "good" "$TESTSUITE/malloc/good_malloc_rand_01.c"
run_case "good_malloc_rand_01_guarded" "tier1" "good" "$TESTSUITE/malloc/good_malloc_rand_01_guarded.c"

run_case "bad_malloc_precomputed_01"  "tier1" "bad"  "$TESTSUITE/malloc/bad_malloc_precomputed_01.c"
run_case "good_malloc_precomputed_01" "tier1" "good" "$TESTSUITE/malloc/good_malloc_precomputed_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_malloc_return_01"     "tier2" "bad"  "$TESTSUITE/interprocedural/bad_malloc_return_01.c"
run_case "good_malloc_interproc_01" "tier2" "good" "$TESTSUITE/interprocedural/good_malloc_interproc_01.c"
run_case "bad_malloc_interproc_01"  "tier2" "bad"  \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01a.c" \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01b.c"

run_case "bad_malloc_struct_01"  "tier2" "bad"  "$TESTSUITE/struct/bad_malloc_struct_01.c"
run_case "good_malloc_struct_01" "tier2" "good" "$TESTSUITE/struct/good_malloc_struct_01.c"

# =======================================================================
# TIER 3 — Known limitation cases
# =======================================================================
echo "=== TIER 3: Known limitation cases ==="
echo

run_case "bad_malloc_struct_precomp_01"  "tier3" "bad"  "$TESTSUITE/struct/bad_malloc_struct_precomp_01.c"
run_case "good_malloc_struct_precomp_01" "tier3" "good" "$TESTSUITE/struct/good_malloc_struct_precomp_01.c"

echo "========================================"
echo " Results saved to : $RESULTS"
echo "========================================"
