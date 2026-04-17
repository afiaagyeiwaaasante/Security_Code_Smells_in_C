#!/usr/bin/env bash
# detectors/detect_dangerous_function.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: dangerous_function
# Detects: calls to inherently dangerous C functions that have no safe variant
#           Covers: gets, strcpy, strcat, sprintf, vsprintf, scanf, sscanf
# Severity: error [dangerousFunction]
#
# Strategy:
#   srcQL UNION query matches any function body containing a call to one of the
#   banned functions in a single pass.
#
#   Position extraction (XPath on srcQL result):
#   - Call site     : pos:start of the dangerous call          → finding
#   - Variable name : first argument passed to the call
#
# Requires: srcml, xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: dangerous_function ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST) UNION FIND $T $FUNC($PARAMS) {} CONTAINS strcpy($DST, $SRC) UNION FIND $T $FUNC($PARAMS) {} CONTAINS strcat($DST, $SRC) UNION FIND $T $FUNC($PARAMS) {} CONTAINS sprintf($BUF, $FMT) UNION FIND $T $FUNC($PARAMS) {} CONTAINS vsprintf($BUF, $FMT, $AP) UNION FIND $T $FUNC($PARAMS) {} CONTAINS scanf($FMT, $BUF) UNION FIND $T $FUNC($PARAMS) {} CONTAINS sscanf($STR, $FMT, $BUF)'

echo "    query  : $QUERY"
echo

# -----------------------------------------------------------------------
# Run the srcQL query
# -----------------------------------------------------------------------
TMPRESULT=$(mktemp /tmp/df_result_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if [ -z "$(grep '<function' "$TMPRESULT")" ]; then
    echo "[ dangerous_function ] No smell detected."
    exit 0
fi

# -----------------------------------------------------------------------
# Extract filename
# -----------------------------------------------------------------------
echo "--- extracting positions ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# -----------------------------------------------------------------------
# Extract ALL dangerous call positions — one LINE:COL:FUNCNAME:VARNAME per occurrence
# -----------------------------------------------------------------------
POSITIONS=$(python3 << PYEOF
import re

BANNED = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf"}

with open("$TMPRESULT") as f:
    content = f.read()

CALL_RE = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>'
    r'\s*<name[^>]*>\s*(\w+)\s*</name>'
    r'.*?<argument\b[^>]*>.*?<name[^>]*>([^<\s]+)</name>',
    re.DOTALL
)

for m in CALL_RE.finditer(content):
    dangerous_func = m.group(3).strip()
    if dangerous_func in BANNED:
        print(f"{m.group(1)}:{m.group(2)}:{dangerous_func}:{m.group(4).strip()}")
PYEOF
)

if [ -z "$POSITIONS" ]; then
    echo "    warning: could not determine call sites — skipping"
    echo "[ dangerous_function ] 0 finding(s) written to $FINDINGS"
    exit 0
fi

# -----------------------------------------------------------------------
# Emit one finding per dangerous call
# -----------------------------------------------------------------------
echo "--- building findings ---"

declare -A REPLACEMENT
REPLACEMENT[gets]="fgets(buf, size, stdin)"
REPLACEMENT[strcpy]="strncpy(dst, src, n) or strlcpy"
REPLACEMENT[strcat]="strncat(dst, src, n) or strlcat"
REPLACEMENT[sprintf]="snprintf(buf, size, fmt, ...)"
REPLACEMENT[vsprintf]="vsnprintf(buf, size, fmt, ap)"
REPLACEMENT[scanf]="scanf with explicit width (e.g. \"%Ns\")"
REPLACEMENT[sscanf]="sscanf with explicit width (e.g. \"%Ns\")"

COUNT=0
while IFS=: read -r CALL_LINE CALL_COL DANGEROUS_FUNC VARNAME; do
    COUNT=$((COUNT + 1))
    REPL="${REPLACEMENT[$DANGEROUS_FUNC]:-a safe bounded alternative}"
    write_finding \
        --findings  "$FINDINGS" \
        --detector  "dangerous_function" \
        --severity  "error" \
        --classification  "vulnerability" \
        --rule      "dangerousFunction" \
        --file      "$FILENAME" \
        --line      "$CALL_LINE" \
        --col       "$CALL_COL" \
        --varname   "${VARNAME:-$DANGEROUS_FUNC}" \
        --note-line "$CALL_LINE" \
        --note-col  "$CALL_COL" \
        --note-msg  "${DANGEROUS_FUNC}() is dangerous — use ${REPL} instead"
    echo "    finding $COUNT: ${FILENAME}:${CALL_LINE}:${CALL_COL} — ${DANGEROUS_FUNC}(${VARNAME})"
done <<< "$POSITIONS"

echo
echo "[ dangerous_function ] $COUNT finding(s) written to $FINDINGS"
