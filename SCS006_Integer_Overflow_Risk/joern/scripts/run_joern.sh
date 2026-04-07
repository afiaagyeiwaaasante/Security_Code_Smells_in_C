#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on representative CWE-190 test cases and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether an integer overflow smell was detected
#
# Detection query:
#   Find arithmetic operations (*, +, ++) whose operand variables are not
#   guarded by a comparison against INT_MAX (or similar) on any path.
#   Implemented as: find binary * or + calls where no sibling call site
#   does a comparison with a name matching "INT_MAX|CHAR_MAX|..." in the
#   same method.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE190"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

mkdir -p "$(dirname "$RESULTS")"
> "$RESULTS"

echo "========================================"
echo " SCS006 — Joern Benchmark"
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

// Find arithmetic operators (* or +) in the CPG
val arithOps = cpg.call
  .nameExact("<operator>.multiplication", "<operator>.addition",
              "<operator>.preIncrement", "<operator>.postIncrement")

// Find any identifier named INT_MAX / CHAR_MAX / etc. used in a comparison
val maxConstants = Set("INT_MAX","CHAR_MAX","SHRT_MAX","UINT_MAX","INT64_MAX","LLONG_MAX")
val guardedMethods = cpg.call
  .nameExact("<operator>.lessThan","<operator>.lessEqualsThan",
             "<operator>.greaterThan","<operator>.greaterEqualsThan")
  .argument
  .isIdentifier
  .filter(i => maxConstants.contains(i.name))
  .method
  .name
  .toSet

// Overflow risk: arithmetic in a method NOT in guardedMethods
val detected = arithOps
  .filter(c => !guardedMethods.contains(c.method.name.head))
  .nonEmpty

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

# Detector 1 — unchecked_multiply
run_case "bad_int_multiply_01"   "$TESTSUITE/multiply/bad_int_multiply_01.c"
run_case "good_int_multiply_01"  "$TESTSUITE/multiply/good_int_multiply_01.c"

# Detector 2 — unchecked_add
run_case "bad_char_add_01"           "$TESTSUITE/add/bad_char_add_01.c"
run_case "good_char_add_01"          "$TESTSUITE/add/good_char_add_01.c"
run_case "bad_unsigned_int_add_01"   "$TESTSUITE/add/bad_unsigned_int_add_01.c"
run_case "good_unsigned_int_add_01"  "$TESTSUITE/add/good_unsigned_int_add_01.c"

# Square (multiply variant)
run_case "bad_int64_square_01"   "$TESTSUITE/square/bad_int64_square_01.c"
run_case "good_int64_square_01"  "$TESTSUITE/square/good_int64_square_01.c"
run_case "bad_short_square_01"   "$TESTSUITE/square/bad_short_square_01.c"
run_case "good_short_square_01"  "$TESTSUITE/square/good_short_square_01.c"

# Detector 3 — unchecked_increment (postfix)
run_case "bad_int_postinc_01"   "$TESTSUITE/postinc/bad_int_postinc_01.c"
run_case "good_int_postinc_01"  "$TESTSUITE/postinc/good_int_postinc_01.c"

# Detector 3 — unchecked_increment (prefix)
run_case "bad_int_preinc_01"    "$TESTSUITE/preinc/bad_int_preinc_01.c"
run_case "good_int_preinc_01"   "$TESTSUITE/preinc/good_int_preinc_01.c"

# C++ class variants
run_case "bad_int_multiply_81"   "$TESTSUITE/cpp_virtual_ref/bad_int_multiply_81.cpp"
run_case "good_int_multiply_81"  "$TESTSUITE/cpp_virtual_ref/good_int_multiply_81.cpp"
run_case "bad_int_multiply_82"   "$TESTSUITE/cpp_virtual_ptr/bad_int_multiply_82.cpp"
run_case "good_int_multiply_82"  "$TESTSUITE/cpp_virtual_ptr/good_int_multiply_82.cpp"
run_case "bad_int_multiply_83"   "$TESTSUITE/cpp_ctor_stack/bad_int_multiply_83.cpp"
run_case "good_int_multiply_83"  "$TESTSUITE/cpp_ctor_stack/good_int_multiply_83.cpp"
run_case "bad_int_multiply_84"   "$TESTSUITE/cpp_ctor_heap/bad_int_multiply_84.cpp"
run_case "good_int_multiply_84"  "$TESTSUITE/cpp_ctor_heap/good_int_multiply_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
