#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS006 tool on representative CWE-190 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE190"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS006 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local FILE="$2"

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    /usr/bin/time -l bash "$SRC_DIR/smell_report.sh" "$FILE" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local SEVERITY="" CLASSIFICATION=""
    if grep -q '"severity":' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
        SEVERITY=$(grep '"severity"' "$TMPOUT" | head -1 | grep -o '"error"\|"warning"' | tr -d '"')
        CLASSIFICATION=$(grep '"classification"' "$TMPOUT" | head -1 | grep -o '"vulnerability"\|"smell"' | tr -d '"')
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","files":["%s"],"detected":%s,"severity":"%s","classification":"%s","wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$(basename "$FILE")" "$DETECTED" "$SEVERITY" "$CLASSIFICATION" \
        "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected       : $DETECTED"
    echo "    severity       : ${SEVERITY:-(none)}"
    echo "    classification : ${CLASSIFICATION:-(none)}"
    echo "    wall time      : ${WALL_TIME}s"
    echo "    peak RSS       : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# Detector 1 — unchecked_multiply
# bad_int_multiply_01 uses rand() → no taint → warning/smell
run_case "bad_int_multiply_01"    "$TESTSUITE/multiply/bad_int_multiply_01.c"
run_case "good_int_multiply_01"   "$TESTSUITE/multiply/good_int_multiply_01.c"
run_case "smell_int_multiply_01"  "$TESTSUITE/multiply/smell_int_multiply_01.c"

# Detector 2 — unchecked_add
# bad_char_add_01 uses fscanf → taint present → error/vulnerability
run_case "bad_char_add_01"           "$TESTSUITE/add/bad_char_add_01.c"
run_case "good_char_add_01"          "$TESTSUITE/add/good_char_add_01.c"
run_case "smell_char_add_01"         "$TESTSUITE/add/smell_char_add_01.c"
run_case "bad_unsigned_int_add_01"   "$TESTSUITE/add/bad_unsigned_int_add_01.c"
run_case "good_unsigned_int_add_01"  "$TESTSUITE/add/good_unsigned_int_add_01.c"

# Square (multiply variant)
# bad_int64_square_01 uses rand() → no taint → warning/smell
run_case "bad_int64_square_01"    "$TESTSUITE/square/bad_int64_square_01.c"
run_case "good_int64_square_01"   "$TESTSUITE/square/good_int64_square_01.c"
run_case "smell_int64_square_01"  "$TESTSUITE/square/smell_int64_square_01.c"
run_case "bad_short_square_01"    "$TESTSUITE/square/bad_short_square_01.c"
run_case "good_short_square_01"   "$TESTSUITE/square/good_short_square_01.c"

# Detector 3 — unchecked_increment (postfix)
run_case "bad_int_postinc_01"    "$TESTSUITE/postinc/bad_int_postinc_01.c"
run_case "good_int_postinc_01"   "$TESTSUITE/postinc/good_int_postinc_01.c"
run_case "smell_int_postinc_01"  "$TESTSUITE/postinc/smell_int_postinc_01.c"

# Detector 3 — unchecked_increment (prefix)
run_case "bad_int_preinc_01"    "$TESTSUITE/preinc/bad_int_preinc_01.c"
run_case "good_int_preinc_01"   "$TESTSUITE/preinc/good_int_preinc_01.c"

# NOTE: interprocedural cases (bad_int_add_22a/b, bad_int_multiply_22a/b) require
# multi-file analysis — not benchmarked here (no smell_report_multi.sh for SCS006).

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
