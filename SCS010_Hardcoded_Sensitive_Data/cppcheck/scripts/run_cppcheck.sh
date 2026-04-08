#!/usr/bin/env bash
# cppcheck/scripts/run_cppcheck.sh
# Runs cppcheck on representative CWE-259 test cases and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a hardcoded credential smell was detected
#
# Detection keyword: [hardcodedCredentials] — cppcheck checks for
#   hard-coded passwords passed to authentication API calls in its
#   library configuration.
#
# Output: cppcheck/results/cppcheck_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE259"
RESULTS="$SCRIPT_DIR/../results/cppcheck_results.json"

mkdir -p "$(dirname "$RESULTS")"
> "$RESULTS"

echo "========================================"
echo " SCS010 — cppcheck Benchmark"
echo " cppcheck version: $(cppcheck --version 2>&1)"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    shift
    local FILES=("$@")

    echo "--- $TEST_NAME ---"

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
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"$(basename "${FILES[$i]}")\""
    done
    FILES_JSON+="]"

    printf '{"test":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# Group 1 — password_var
run_case "bad_password_var_01"  "$TESTSUITE/password_var/bad_password_var_01.c"
run_case "good_password_var_01" "$TESTSUITE/password_var/good_password_var_01.c"

# Group 2 — define_const
run_case "bad_define_const_01"  "$TESTSUITE/define_const/bad_define_const_01.c"
run_case "good_define_const_01" "$TESTSUITE/define_const/good_define_const_01.c"

# Group 3 — strcmp_auth
run_case "bad_strcmp_auth_01"  "$TESTSUITE/strcmp_auth/bad_strcmp_auth_01.c"
run_case "good_strcmp_auth_01" "$TESTSUITE/strcmp_auth/good_strcmp_auth_01.c"

# Group 4 — interprocedural (source file)
run_case "bad_password_interprocedural_22a"  "$TESTSUITE/interprocedural/bad_password_interprocedural_22a.c"
run_case "good_password_interprocedural_22b" "$TESTSUITE/interprocedural/good_password_interprocedural_22b.c"

# Group 5 — cpp_class (flow 84)
run_case "bad_password_class_84"  "$TESTSUITE/cpp_class/bad_password_class_84.cpp"
run_case "good_password_class_84" "$TESTSUITE/cpp_class/good_password_class_84.cpp"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
