#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS002 tool on each CWE-680 test case and records:
#   - wall-clock time, peak RSS, detection result, tier, expected outcome
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE680"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS002 — SmellDetect Benchmark"
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
        /usr/bin/time -l bash "$SRC_DIR/smell_report.sh" "${FILES[0]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    else
        /usr/bin/time -l bash "$SRC_DIR/smell_report_multi.sh" "${FILES[@]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    fi

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local FINDING_COUNT
    FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
    FINDING_COUNT=${FINDING_COUNT:-0}

    if [ "$FINDING_COUNT" -gt 0 ]; then
        DETECTED="true"
    else
        DETECTED="false"
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

# =======================================================================
# TIER 1 — Smell pattern variants
# =======================================================================
echo "=== TIER 1: Smell pattern variants ==="
echo

run_case "bad_malloc_01"          "tier1" "bad"  single "$TESTSUITE/malloc/bad_malloc_01.c"
run_case "good_malloc_01"         "tier1" "good" single "$TESTSUITE/malloc/good_malloc_01.c"
run_case "good_malloc_01_guarded" "tier1" "good" single "$TESTSUITE/malloc/good_malloc_01_guarded.c"

run_case "bad_malloc_fixed_01"          "tier1" "bad"  single "$TESTSUITE/malloc/bad_malloc_fixed_01.c"
run_case "good_malloc_fixed_01"         "tier1" "good" single "$TESTSUITE/malloc/good_malloc_fixed_01.c"
run_case "good_malloc_fixed_01_guarded" "tier1" "good" single "$TESTSUITE/malloc/good_malloc_fixed_01_guarded.c"

run_case "bad_malloc_fgets_01"          "tier1" "bad"  single "$TESTSUITE/malloc/bad_malloc_fgets_01.c"
run_case "good_malloc_fgets_01"         "tier1" "good" single "$TESTSUITE/malloc/good_malloc_fgets_01.c"
run_case "good_malloc_fgets_01_guarded" "tier1" "good" single "$TESTSUITE/malloc/good_malloc_fgets_01_guarded.c"

run_case "bad_malloc_rand_01"          "tier1" "bad"  single "$TESTSUITE/malloc/bad_malloc_rand_01.c"
run_case "good_malloc_rand_01"         "tier1" "good" single "$TESTSUITE/malloc/good_malloc_rand_01.c"
run_case "good_malloc_rand_01_guarded" "tier1" "good" single "$TESTSUITE/malloc/good_malloc_rand_01_guarded.c"

run_case "bad_malloc_precomputed_01"  "tier1" "bad"  single "$TESTSUITE/malloc/bad_malloc_precomputed_01.c"
run_case "good_malloc_precomputed_01" "tier1" "good" single "$TESTSUITE/malloc/good_malloc_precomputed_01.c"

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_malloc_return_01"     "tier2" "bad"  single "$TESTSUITE/interprocedural/bad_malloc_return_01.c"
run_case "good_malloc_interproc_01" "tier2" "good" single "$TESTSUITE/interprocedural/good_malloc_interproc_01.c"

# Multi-file: size computed in one TU, malloc in another
run_case "bad_malloc_interproc_01" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01a.c" \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01b.c"

# Struct member, direct multiply — srcQL $A*$B binds ctx.count to $A
run_case "bad_malloc_struct_01"  "tier2" "bad"  single "$TESTSUITE/struct/bad_malloc_struct_01.c"
run_case "good_malloc_struct_01" "tier2" "good" single "$TESTSUITE/struct/good_malloc_struct_01.c"

# =======================================================================
# TIER 3 — Known limitation cases
# =======================================================================
echo "=== TIER 3: Known limitation cases (expected: missed) ==="
echo

# Struct member + precomputed: sz = ctx.count * sizeof — Detector 1 sees no *
# in malloc arg; Detector 2 pattern $SZ = $A * $B fails because $A is a
# member-access expression, not a simple identifier.
run_case "bad_malloc_struct_precomp_01"  "tier3" "bad"  single "$TESTSUITE/struct/bad_malloc_struct_precomp_01.c"
run_case "good_malloc_struct_precomp_01" "tier3" "good" single "$TESTSUITE/struct/good_malloc_struct_precomp_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
