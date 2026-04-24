#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-476 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a null pointer smell was detected
#
# Detection queries:
#   1. ptr = NULL then ptr->field or ptr[idx] in same function
#   2. bitwise & used in condition (binary_if pattern)
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS003 — Joern Benchmark"
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
// Pattern 1: ptr = NULL then ptr->field or ptr[idx]
val nullPtrs = cpg.assignment
  .where(_.source.isLiteral.codeExact("0"))
  .target.isIdentifier.name.toSet
val derefHits = cpg.call
  .name("<operator>.indirectFieldAccess", "<operator>.indirectIndexAccess")
  .argument(1).isIdentifier
  .filter(i => nullPtrs.contains(i.name))
  .l
// Pattern 2: bitwise & used in condition (binary_if)
val bitwiseHits = cpg.call.name("<operator>.and")
  .where(_.argument.isCall.name("<operator>.notEquals", "<operator>.equals"))
  .l
val detected = derefHits.nonEmpty || bitwiseHits.nonEmpty
println(s"JOERN_RESULT:$detected")
SCALAEOF

    # Substitute the actual source path
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

# --- binary_if (Detector 1) ---
run_case "bad_binary_if_01"     "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_01.c"     '["bad_binary_if_01.c"]'
run_case "bad_binary_if_flow02" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow02.c" '["bad_binary_if_flow02.c"]'
run_case "bad_binary_if_flow05" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow05.c" '["bad_binary_if_flow05.c"]'
run_case "bad_binary_if_flow11" "tier1" "bad"  "$TESTSUITE/binary_if/bad_binary_if_flow11.c" '["bad_binary_if_flow11.c"]'
run_case "good_binary_if_01"    "tier1" "good" "$TESTSUITE/binary_if/good_binary_if_01.c"    '["good_binary_if_01.c"]'

# --- deref_no_check (Detectors 3 & 4) ---
run_case "bad_null_deref_01"    "tier1" "bad"  "$TESTSUITE/deref_no_check/bad_null_deref_01.c"  '["bad_null_deref_01.c"]'
run_case "good_guarded_01"      "tier1" "good" "$TESTSUITE/deref_no_check/good_guarded_01.c"    '["good_guarded_01.c"]'
run_case "smell_no_guard_01"    "tier1" "bad"  "$TESTSUITE/deref_no_check/smell_no_guard_01.c"  '["smell_no_guard_01.c"]'

# --- char (Detectors 3 & 4) ---
run_case "bad_char_01"          "tier1" "bad"  "$TESTSUITE/char/bad_char_01.c"   '["bad_char_01.c"]'
run_case "bad_char_01b"         "tier1" "bad"  "$TESTSUITE/char/bad_char_01b.c"  '["bad_char_01b.c"]'
run_case "good_char_01"         "tier1" "good" "$TESTSUITE/char/good_char_01.c"  '["good_char_01.c"]'
run_case "smell_char_01b"       "tier1" "bad"  "$TESTSUITE/char/smell_char_01b.c" '["smell_char_01b.c"]'
run_case "good_char_01b"        "tier1" "good" "$TESTSUITE/char/good_char_01b.c" '["good_char_01b.c"]'

# --- deref_after_check (Detector 5) ---
run_case "bad_deref_after_check_01" "tier1" "bad" "$TESTSUITE/after_check/bad_deref_after_check_01.c" '["bad_deref_after_check_01.c"]'

# --- check_after_deref (Detector 6) ---
run_case "bad_check_after_deref_01" "tier1" "bad" "$TESTSUITE/check_after_deref/bad_check_after_deref_01.c" '["bad_check_after_deref_01.c"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_interprocedural_01"      "tier2" "bad" "$TESTSUITE/interprocedural/bad_interprocedural_01.c"      '["bad_interprocedural_01.c"]'
run_case "good_interprocedural_01"     "tier2" "bad" "$TESTSUITE/interprocedural/good_interprocedural_01.c"     '["good_interprocedural_01.c"]'
run_case "bad_char_interprocedural_01" "tier2" "bad" "$TESTSUITE/interprocedural/bad_char_interprocedural_01.c" '["bad_char_interprocedural_01.c"]'

TMPDIR_INTERPROC=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_char_interprocedural_22a.c" "$TMPDIR_INTERPROC/"
cp "$TESTSUITE/interprocedural/bad_char_interprocedural_22b.c" "$TMPDIR_INTERPROC/"
run_case "bad_char_interprocedural_22" "tier2" "bad" "$TMPDIR_INTERPROC" '["bad_char_interprocedural_22a.c","bad_char_interprocedural_22b.c"]'
rm -rf "$TMPDIR_INTERPROC"

# =======================================================================
# TIER 3 — Known limitation cases
# =======================================================================
echo "=== TIER 3: Known limitation cases ==="
echo

run_case "smell_char_01"            "tier3" "bad" "$TESTSUITE/char/smell_char_01.c"                    '["smell_char_01.c"]'
run_case "bad_struct_ptr_to_ptr_01" "tier3" "bad" "$TESTSUITE/struct/bad_struct_ptr_to_ptr_01.c"       '["bad_struct_ptr_to_ptr_01.c"]'
run_case "bad_struct_copy_01"       "tier3" "bad" "$TESTSUITE/struct/bad_struct_copy_01.c"             '["bad_struct_copy_01.c"]'
run_case "bad_struct_union_01"      "tier3" "bad" "$TESTSUITE/struct/bad_struct_union_01.c"            '["bad_struct_union_01.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
