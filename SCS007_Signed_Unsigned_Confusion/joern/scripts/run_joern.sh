#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-195 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a signed-to-unsigned conversion smell was detected
#
# Detection query:
#   Find functions that call malloc/memcpy/memmove/strncpy (the sinks) where
#   no sibling call in the same method uses a greaterThan (>) or
#   greaterEqualsThan (>=) comparison with the literal 0 or 1.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE195"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS007 — Joern Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local SOURCE_PATH="$4"
    local FILES_JSON="$5"

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local SCALA_SCRIPT TMPOUT TIMEFILE
    SCALA_SCRIPT=$(mktemp /tmp/joern_script_XXXXXX.sc)
    TMPOUT=$(mktemp /tmp/joern_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/joern_time_XXXXXX)

    cat > "$SCALA_SCRIPT" << 'SCALAEOF'
importCode("SOURCE_PATH_PLACEHOLDER")

// Methods that call a size-consuming sink (malloc, memcpy, memmove, strncpy)
val sinkMethods = cpg.call
  .nameExact("malloc", "memcpy", "memmove", "strncpy")
  .method
  .name
  .toSet

// Methods that have a positivity guard: greaterThan or greaterEqualsThan
// comparison with literal 0 or 1
val guardedMethods = cpg.call
  .nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan")
  .where(_.argument.isLiteral.filter(l => l.code == "0" || l.code == "1"))
  .method
  .name
  .toSet

// Unguarded sink = has sink call but no positivity guard in the same method
val unguarded = sinkMethods -- guardedMethods
val detected  = unguarded.nonEmpty

println(s"JOERN_RESULT:$detected")
SCALAEOF

    sed -i '' "s|SOURCE_PATH_PLACEHOLDER|${SOURCE_PATH}|g" "$SCALA_SCRIPT"

    /usr/bin/time -l joern --script "$SCALA_SCRIPT" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q 'JOERN_RESULT:true' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","tier":"%s","expected":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$SCALA_SCRIPT" "$TMPOUT" "$TIMEFILE"
}

# =======================================================================
# TIER 1 — Smell pattern variants
# =======================================================================
echo "=== TIER 1: Smell pattern variants ==="
echo

run_case "bad_malloc_size_01"    "tier1" "bad"  "$TESTSUITE/malloc_size/bad_malloc_size_01.c"    '["bad_malloc_size_01.c"]'
run_case "good_malloc_size_01"   "tier1" "good" "$TESTSUITE/malloc_size/good_malloc_size_01.c"   '["good_malloc_size_01.c"]'
run_case "smell_malloc_size_01"  "tier1" "bad"  "$TESTSUITE/malloc_size/smell_malloc_size_01.c"  '["smell_malloc_size_01.c"]'

run_case "bad_memcpy_count_01"    "tier1" "bad"  "$TESTSUITE/memcpy_count/bad_memcpy_count_01.c"    '["bad_memcpy_count_01.c"]'
run_case "good_memcpy_count_01"   "tier1" "good" "$TESTSUITE/memcpy_count/good_memcpy_count_01.c"   '["good_memcpy_count_01.c"]'
run_case "smell_memcpy_count_01"  "tier1" "bad"  "$TESTSUITE/memcpy_count/smell_memcpy_count_01.c"  '["smell_memcpy_count_01.c"]'

run_case "bad_strncpy_count_01"    "tier1" "bad"  "$TESTSUITE/strncpy_count/bad_strncpy_count_01.c"    '["bad_strncpy_count_01.c"]'
run_case "good_strncpy_count_01"   "tier1" "good" "$TESTSUITE/strncpy_count/good_strncpy_count_01.c"   '["good_strncpy_count_01.c"]'
run_case "smell_strncpy_count_01"  "tier1" "bad"  "$TESTSUITE/strncpy_count/smell_strncpy_count_01.c"  '["smell_strncpy_count_01.c"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_signed_malloc_22b"   "tier2" "bad"  "$TESTSUITE/interprocedural/bad_signed_malloc_22b.c"   '["bad_signed_malloc_22b.c"]'
run_case "good_signed_malloc_22b"  "tier2" "good" "$TESTSUITE/interprocedural/good_signed_malloc_22b.c"  '["good_signed_malloc_22b.c"]'

run_case "bad_signed_malloc_84"   "tier2" "bad"  "$TESTSUITE/cpp_class/bad_signed_malloc_84.cpp"   '["bad_signed_malloc_84.cpp"]'
run_case "good_signed_malloc_84"  "tier2" "good" "$TESTSUITE/cpp_class/good_signed_malloc_84.cpp"  '["good_signed_malloc_84.cpp"]'

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural source-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo

run_case "bad_signed_malloc_22a"   "tier3" "bad"  "$TESTSUITE/interprocedural/bad_signed_malloc_22a.c"   '["bad_signed_malloc_22a.c"]'
run_case "good_signed_malloc_22a"  "tier3" "good" "$TESTSUITE/interprocedural/good_signed_malloc_22a.c"  '["good_signed_malloc_22a.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
