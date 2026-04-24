#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-190 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether an integer overflow smell was detected
#
# Detection query:
#   Find arithmetic operations (*, +, ++) whose operand variables are not
#   guarded by a comparison against INT_MAX (or similar) on any path.
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

run_case "bad_char_add_01"           "tier1" "bad"  "$TESTSUITE/add/bad_char_add_01.c"           '["bad_char_add_01.c"]'
run_case "good_char_add_01"          "tier1" "good" "$TESTSUITE/add/good_char_add_01.c"          '["good_char_add_01.c"]'
run_case "smell_char_add_01"         "tier1" "bad"  "$TESTSUITE/add/smell_char_add_01.c"         '["smell_char_add_01.c"]'
run_case "bad_unsigned_int_add_01"   "tier1" "bad"  "$TESTSUITE/add/bad_unsigned_int_add_01.c"   '["bad_unsigned_int_add_01.c"]'
run_case "good_unsigned_int_add_01"  "tier1" "good" "$TESTSUITE/add/good_unsigned_int_add_01.c"  '["good_unsigned_int_add_01.c"]'

run_case "bad_int_multiply_01"   "tier1" "bad"  "$TESTSUITE/multiply/bad_int_multiply_01.c"   '["bad_int_multiply_01.c"]'
run_case "good_int_multiply_01"  "tier1" "good" "$TESTSUITE/multiply/good_int_multiply_01.c"  '["good_int_multiply_01.c"]'
run_case "smell_int_multiply_01" "tier1" "bad"  "$TESTSUITE/multiply/smell_int_multiply_01.c" '["smell_int_multiply_01.c"]'

run_case "bad_int64_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_int64_square_01.c"    '["bad_int64_square_01.c"]'
run_case "good_int64_square_01"   "tier1" "good" "$TESTSUITE/square/good_int64_square_01.c"   '["good_int64_square_01.c"]'
run_case "smell_int64_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_int64_square_01.c"  '["smell_int64_square_01.c"]'
run_case "bad_short_square_01"    "tier1" "bad"  "$TESTSUITE/square/bad_short_square_01.c"    '["bad_short_square_01.c"]'
run_case "good_short_square_01"   "tier1" "good" "$TESTSUITE/square/good_short_square_01.c"   '["good_short_square_01.c"]'
run_case "smell_short_square_01"  "tier1" "bad"  "$TESTSUITE/square/smell_short_square_01.c"  '["smell_short_square_01.c"]'

run_case "bad_int_postinc_01"    "tier1" "bad"  "$TESTSUITE/postinc/bad_int_postinc_01.c"    '["bad_int_postinc_01.c"]'
run_case "good_int_postinc_01"   "tier1" "good" "$TESTSUITE/postinc/good_int_postinc_01.c"   '["good_int_postinc_01.c"]'
run_case "smell_int_postinc_01"  "tier1" "bad"  "$TESTSUITE/postinc/smell_int_postinc_01.c"  '["smell_int_postinc_01.c"]'

run_case "bad_int_preinc_01"    "tier1" "bad"  "$TESTSUITE/preinc/bad_int_preinc_01.c"    '["bad_int_preinc_01.c"]'
run_case "good_int_preinc_01"   "tier1" "good" "$TESTSUITE/preinc/good_int_preinc_01.c"   '["good_int_preinc_01.c"]'
run_case "smell_int_preinc_01"  "tier1" "bad"  "$TESTSUITE/preinc/smell_int_preinc_01.c"  '["smell_int_preinc_01.c"]'

# =======================================================================
# TIER 2 — Context variants (C++ class patterns)
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_int_multiply_81"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ref/bad_int_multiply_81.cpp"  '["bad_int_multiply_81.cpp"]'
run_case "good_int_multiply_81"  "tier2" "good" "$TESTSUITE/cpp_virtual_ref/good_int_multiply_81.cpp" '["good_int_multiply_81.cpp"]'
run_case "bad_int_multiply_82"   "tier2" "bad"  "$TESTSUITE/cpp_virtual_ptr/bad_int_multiply_82.cpp"  '["bad_int_multiply_82.cpp"]'
run_case "good_int_multiply_82"  "tier2" "good" "$TESTSUITE/cpp_virtual_ptr/good_int_multiply_82.cpp" '["good_int_multiply_82.cpp"]'
run_case "bad_int_multiply_83"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_stack/bad_int_multiply_83.cpp"   '["bad_int_multiply_83.cpp"]'
run_case "good_int_multiply_83"  "tier2" "good" "$TESTSUITE/cpp_ctor_stack/good_int_multiply_83.cpp"  '["good_int_multiply_83.cpp"]'
run_case "bad_int_multiply_84"   "tier2" "bad"  "$TESTSUITE/cpp_ctor_heap/bad_int_multiply_84.cpp"    '["bad_int_multiply_84.cpp"]'
run_case "good_int_multiply_84"  "tier2" "good" "$TESTSUITE/cpp_ctor_heap/good_int_multiply_84.cpp"   '["good_int_multiply_84.cpp"]'

# =======================================================================
# TIER 3 — Interprocedural multi-file cases (copy to temp dir for Joern)
# =======================================================================
echo "=== TIER 3: Interprocedural multi-file cases ==="
echo

TMPDIR_I1=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_int_add_22a.c" "$TMPDIR_I1/"
cp "$TESTSUITE/interprocedural/bad_int_add_22b.c" "$TMPDIR_I1/"
run_case "bad_int_add_22" "tier3" "bad" "$TMPDIR_I1" '["bad_int_add_22a.c","bad_int_add_22b.c"]'
rm -rf "$TMPDIR_I1"

TMPDIR_I2=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/good_int_add_22a.c" "$TMPDIR_I2/"
cp "$TESTSUITE/interprocedural/good_int_add_22b.c" "$TMPDIR_I2/"
run_case "good_int_add_22" "tier3" "good" "$TMPDIR_I2" '["good_int_add_22a.c","good_int_add_22b.c"]'
rm -rf "$TMPDIR_I2"

TMPDIR_I3=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_int_multiply_22a.c" "$TMPDIR_I3/"
cp "$TESTSUITE/interprocedural/bad_int_multiply_22b.c" "$TMPDIR_I3/"
run_case "bad_int_multiply_22" "tier3" "bad" "$TMPDIR_I3" '["bad_int_multiply_22a.c","bad_int_multiply_22b.c"]'
rm -rf "$TMPDIR_I3"

TMPDIR_I4=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/good_int_multiply_22a.c" "$TMPDIR_I4/"
cp "$TESTSUITE/interprocedural/good_int_multiply_22b.c" "$TMPDIR_I4/"
run_case "good_int_multiply_22" "tier3" "good" "$TMPDIR_I4" '["good_int_multiply_22a.c","good_int_multiply_22b.c"]'
rm -rf "$TMPDIR_I4"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
