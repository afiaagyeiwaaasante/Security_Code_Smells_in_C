#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-416 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a use-after-free smell was detected
#
# Detection query:
#   free/delete call followed by a use of the same identifier in the same function.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE416"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS004 — Joern Benchmark"
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

    local SCALA_SCRIPT
    SCALA_SCRIPT=$(mktemp /tmp/joern_script_XXXXXX.sc)
    cat > "$SCALA_SCRIPT" << 'SCALAEOF'
importCode("SOURCE_PATH_PLACEHOLDER")
// Find free/delete calls, then check if the freed variable is used after
val freedVars = cpg.call.name("free", "delete", "<operator>.delete")
  .argument(1).isIdentifier.name.toSet
// Look for any use of those variables after a free/delete call
val hits = cpg.identifier
  .filter(i => freedVars.contains(i.name))
  .inCall
  .nameNot("free", "delete", "<operator>.delete")
  .l
val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
SCALAEOF

    sed -i '' "s|SOURCE_PATH_PLACEHOLDER|${SOURCE_PATH}|g" "$SCALA_SCRIPT"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/joern_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/joern_time_XXXXXX)

    /usr/bin/time -l joern --script "$SCALA_SCRIPT" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q "JOERN_RESULT:true" "$TMPOUT" 2>/dev/null; then
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

run_case "bad_use_after_free_char_01"    "tier1" "bad"  "$TESTSUITE/char/bad_use_after_free_char_01.c"   '["bad_use_after_free_char_01.c"]'
run_case "good_use_after_free_char_01"   "tier1" "good" "$TESTSUITE/char/good_use_after_free_char_01.c"  '["good_use_after_free_char_01.c"]'
run_case "bad_use_after_free_int_01"     "tier1" "bad"  "$TESTSUITE/int/bad_use_after_free_int_01.c"     '["bad_use_after_free_int_01.c"]'
run_case "good_use_after_free_int_01"    "tier1" "good" "$TESTSUITE/int/good_use_after_free_int_01.c"    '["good_use_after_free_int_01.c"]'
run_case "bad_use_after_free_int64_01"   "tier1" "bad"  "$TESTSUITE/int64/bad_use_after_free_int64_01.c" '["bad_use_after_free_int64_01.c"]'
run_case "good_use_after_free_int64_01"  "tier1" "good" "$TESTSUITE/int64/good_use_after_free_int64_01.c" '["good_use_after_free_int64_01.c"]'
run_case "bad_use_after_free_long_01"    "tier1" "bad"  "$TESTSUITE/long/bad_use_after_free_long_01.c"   '["bad_use_after_free_long_01.c"]'
run_case "good_use_after_free_long_01"   "tier1" "good" "$TESTSUITE/long/good_use_after_free_long_01.c"  '["good_use_after_free_long_01.c"]'

run_case "bad_double_free_01"            "tier1" "bad"  "$TESTSUITE/char/bad_double_free_01.c"            '["bad_double_free_01.c"]'
run_case "good_double_free_01"           "tier1" "good" "$TESTSUITE/char/good_double_free_01.c"           '["good_double_free_01.c"]'

run_case "bad_delete_array_char_01"      "tier1" "bad"  "$TESTSUITE/delete_array_char/bad_delete_array_char_01.cpp"   '["bad_delete_array_char_01.cpp"]'
run_case "good_delete_array_char_01"     "tier1" "good" "$TESTSUITE/delete_array_char/good_delete_array_char_01.cpp"  '["good_delete_array_char_01.cpp"]'
run_case "bad_delete_array_int64_01"     "tier1" "bad"  "$TESTSUITE/delete_array_int64_t/bad_delete_array_int64_01.cpp"   '["bad_delete_array_int64_01.cpp"]'
run_case "good_delete_array_int64_01"    "tier1" "good" "$TESTSUITE/delete_array_int64_t/good_delete_array_int64_01.cpp"  '["good_delete_array_int64_01.cpp"]'
run_case "bad_delete_array_long_01"      "tier1" "bad"  "$TESTSUITE/delete_array_long/bad_delete_array_long_01.cpp"   '["bad_delete_array_long_01.cpp"]'
run_case "good_delete_array_long_01"     "tier1" "good" "$TESTSUITE/delete_array_long/good_delete_array_long_01.cpp"  '["good_delete_array_long_01.cpp"]'
run_case "bad_delete_array_wchar_01"     "tier1" "bad"  "$TESTSUITE/delete_array_wchar_t/bad_delete_array_wchar_01.cpp"   '["bad_delete_array_wchar_01.cpp"]'
run_case "good_delete_array_wchar_01"    "tier1" "good" "$TESTSUITE/delete_array_wchar_t/good_delete_array_wchar_01.cpp"  '["good_delete_array_wchar_01.cpp"]'

run_case "bad_return_freed_ptr_01"       "tier1" "bad"  "$TESTSUITE/freed_pointer/bad_return_freed_ptr_01.c"    '["bad_return_freed_ptr_01.c"]'
run_case "good_return_freed_ptr_01"      "tier1" "good" "$TESTSUITE/freed_pointer/good_return_freed_ptr_01.c"   '["good_return_freed_ptr_01.c"]'

run_case "bad_new_delete_char_01"        "tier1" "bad"  "$TESTSUITE/new_delete_char/bad_new_delete_char_01.cpp"   '["bad_new_delete_char_01.cpp"]'
run_case "good_new_delete_char_01"       "tier1" "good" "$TESTSUITE/new_delete_char/good_new_delete_char_01.cpp"  '["good_new_delete_char_01.cpp"]'
run_case "bad_new_delete_int_01"         "tier1" "bad"  "$TESTSUITE/new_delete_int/bad_new_delete_int_01.cpp"     '["bad_new_delete_int_01.cpp"]'
run_case "good_new_delete_int_01"        "tier1" "good" "$TESTSUITE/new_delete_int/good_new_delete_int_01.cpp"    '["good_new_delete_int_01.cpp"]'
run_case "bad_new_delete_int64_01"       "tier1" "bad"  "$TESTSUITE/new_delete_int64_t/bad_new_delete_int64_01.cpp"   '["bad_new_delete_int64_01.cpp"]'
run_case "good_new_delete_int64_01"      "tier1" "good" "$TESTSUITE/new_delete_int64_t/good_new_delete_int64_01.cpp"  '["good_new_delete_int64_01.cpp"]'
run_case "bad_new_delete_long_01"        "tier1" "bad"  "$TESTSUITE/new_delete_long/bad_new_delete_long_01.cpp"   '["bad_new_delete_long_01.cpp"]'
run_case "good_new_delete_long_01"       "tier1" "good" "$TESTSUITE/new_delete_long/good_new_delete_long_01.cpp"  '["good_new_delete_long_01.cpp"]'
run_case "bad_new_delete_wchar_01"       "tier1" "bad"  "$TESTSUITE/new_delete_wchar_t/bad_new_delete_wchar_01.cpp"   '["bad_new_delete_wchar_01.cpp"]'
run_case "good_new_delete_wchar_01"      "tier1" "good" "$TESTSUITE/new_delete_wchar_t/good_new_delete_wchar_01.cpp"  '["good_new_delete_wchar_01.cpp"]'

run_case "bad_operator_equals_01"        "tier1" "bad"  "$TESTSUITE/operator_equals/bad_operator_equals_01.cpp"   '["bad_operator_equals_01.cpp"]'
run_case "good_operator_equals_01"       "tier1" "good" "$TESTSUITE/operator_equals/good_operator_equals_01.cpp"  '["good_operator_equals_01.cpp"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_use_after_free_struct_01"  "tier2" "bad"  "$TESTSUITE/struct/bad_use_after_free_struct_01.c"   '["bad_use_after_free_struct_01.c"]'
run_case "good_use_after_free_struct_01" "tier2" "good" "$TESTSUITE/struct/good_use_after_free_struct_01.c"  '["good_use_after_free_struct_01.c"]'

run_case "bad_delete_array_struct_01"    "tier2" "bad"  "$TESTSUITE/delete_array_struct/bad_delete_array_struct_01.cpp"   '["bad_delete_array_struct_01.cpp"]'
run_case "good_delete_array_struct_01"   "tier2" "good" "$TESTSUITE/delete_array_struct/good_delete_array_struct_01.cpp"  '["good_delete_array_struct_01.cpp"]'

run_case "bad_new_delete_struct_01"      "tier2" "bad"  "$TESTSUITE/new_delete_struct/bad_new_delete_struct_01.cpp"   '["bad_new_delete_struct_01.cpp"]'
run_case "good_new_delete_struct_01"     "tier2" "good" "$TESTSUITE/new_delete_struct/good_new_delete_struct_01.cpp"  '["good_new_delete_struct_01.cpp"]'
run_case "bad_new_delete_class_01"       "tier2" "bad"  "$TESTSUITE/new_delete_class/bad_new_delete_class_01.cpp"    '["bad_new_delete_class_01.cpp"]'
run_case "good_new_delete_class_01"      "tier2" "good" "$TESTSUITE/new_delete_class/good_new_delete_class_01.cpp"   '["good_new_delete_class_01.cpp"]'

TMPDIR_I1=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22a.c" "$TMPDIR_I1/"
cp "$TESTSUITE/interprocedural/bad_interprocedural_uaf_long_22b.c" "$TMPDIR_I1/"
run_case "bad_interprocedural_uaf_long_22" "tier2" "bad" "$TMPDIR_I1" '["bad_interprocedural_uaf_long_22a.c","bad_interprocedural_uaf_long_22b.c"]'
rm -rf "$TMPDIR_I1"

TMPDIR_I2=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62a.cpp" "$TMPDIR_I2/"
cp "$TESTSUITE/interprocedural/bad_interprocedural_delete_array_char_62b.cpp" "$TMPDIR_I2/"
run_case "bad_interprocedural_delete_array_char_62" "tier2" "bad" "$TMPDIR_I2" '["bad_interprocedural_delete_array_char_62a.cpp","bad_interprocedural_delete_array_char_62b.cpp"]'
rm -rf "$TMPDIR_I2"

TMPDIR_I3=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62a.cpp" "$TMPDIR_I3/"
cp "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_char_62b.cpp" "$TMPDIR_I3/"
run_case "bad_interprocedural_new_delete_char_62" "tier2" "bad" "$TMPDIR_I3" '["bad_interprocedural_new_delete_char_62a.cpp","bad_interprocedural_new_delete_char_62b.cpp"]'
rm -rf "$TMPDIR_I3"

TMPDIR_I4=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62a.cpp" "$TMPDIR_I4/"
cp "$TESTSUITE/interprocedural/bad_interprocedural_new_delete_class_62b.cpp" "$TMPDIR_I4/"
run_case "bad_interprocedural_new_delete_class_62" "tier2" "bad" "$TMPDIR_I4" '["bad_interprocedural_new_delete_class_62a.cpp","bad_interprocedural_new_delete_class_62b.cpp"]'
rm -rf "$TMPDIR_I4"

TMPDIR_I5=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62a.c" "$TMPDIR_I5/"
cp "$TESTSUITE/interprocedural/bad_interprocedural_uaf_struct_62b.c" "$TMPDIR_I5/"
run_case "bad_interprocedural_uaf_struct_62" "tier2" "bad" "$TMPDIR_I5" '["bad_interprocedural_uaf_struct_62a.c","bad_interprocedural_uaf_struct_62b.c"]'
rm -rf "$TMPDIR_I5"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
