#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on representative CWE-195 test cases and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a signed-to-unsigned conversion smell was detected
#
# Detection query:
#   Find functions that call malloc/memcpy/memmove/strncpy (the sinks) where
#   no sibling call in the same method uses a greaterThan (>) or
#   greaterEqualsThan (>=) comparison with the literal 0 or 1.
#   This mirrors the structural guard-check used by our srcML detector.
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
    local SOURCE_PATH="$2"

    echo "--- $TEST_NAME ---"

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

    printf '{"test":"%s","files":["%s"],"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$(basename "$SOURCE_PATH")" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$SCALA_SCRIPT" "$TMPOUT" "$TIMEFILE"
}

# Group 1 — malloc_size
run_case "bad_malloc_size_01"   "$TESTSUITE/malloc_size/bad_malloc_size_01.c"
run_case "good_malloc_size_01"  "$TESTSUITE/malloc_size/good_malloc_size_01.c"

# Group 2 — memcpy_count
run_case "bad_memcpy_count_01"   "$TESTSUITE/memcpy_count/bad_memcpy_count_01.c"
run_case "good_memcpy_count_01"  "$TESTSUITE/memcpy_count/good_memcpy_count_01.c"

# Group 3 — strncpy_count
run_case "bad_strncpy_count_01"   "$TESTSUITE/strncpy_count/bad_strncpy_count_01.c"
run_case "good_strncpy_count_01"  "$TESTSUITE/strncpy_count/good_strncpy_count_01.c"

# Group 4 — interprocedural (sink file)
run_case "bad_signed_malloc_22b"   "$TESTSUITE/interprocedural/bad_signed_malloc_22b.c"
run_case "good_signed_malloc_22b"  "$TESTSUITE/interprocedural/good_signed_malloc_22b.c"

# Group 5 — cpp_class (flow 84)
run_case "bad_signed_malloc_84"   "$TESTSUITE/cpp_class/bad_signed_malloc_84.cpp"
run_case "good_signed_malloc_84"  "$TESTSUITE/cpp_class/good_signed_malloc_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
