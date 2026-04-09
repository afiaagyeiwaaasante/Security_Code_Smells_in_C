#!/usr/bin/env bash
# detectors/detect_overwrite_leak.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: overwrite_leak
# Detects: pointer is reassigned a new malloc() allocation without first
#           freeing the original allocation — the first block is leaked.
# Severity: warning [overwriteLeak]
#
# srcQL query:
#   FIND $T $FUNC() {} CONTAINS $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B)
#
#   Binds $PTR to the LHS pointer variable.  The FOLLOWED BY clause requires
#   that the same $PTR is the target of a second malloc() call later in the
#   same function, with no intervening free($PTR).
#
#   Position: pos:start of the second malloc() call — the overwrite site.
#   Note:     pos:start of the first malloc() call  — the original allocation.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: overwrite_leak ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

TMPRESULT=$(mktemp /tmp/memleak_overwrite_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

QUERY='FIND $T $FUNC() {} CONTAINS malloc($A) FOLLOWED BY malloc($B)'
echo "    query  : $QUERY"
{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "    no overwrite pattern found — no findings."
    echo
    exit 0
fi

echo "--- extracting overwrite sites ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

with open("$TMPRESULT") as f:
    content = f.read()

findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

func_blocks = re.split(r'(?=<function[\s>])', content)

for block in func_blocks:
    if '<function' not in block:
        continue

    fname_m = re.search(r'<function[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    fname = fname_m.group(1).strip() if fname_m else "?"

    # Find all malloc() call positions in order
    malloc_calls = re.findall(
        r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*malloc\s*</name>',
        block)

    if len(malloc_calls) < 2:
        continue  # need at least two malloc calls

    # Check: is there a free() call between the two malloc calls?
    first_line  = int(malloc_calls[0][0])
    second_line = int(malloc_calls[1][0])

    # Extract all free() call line numbers
    free_lines = [int(m) for m in re.findall(
        r'<call\b[^>]*pos:start="(\d+):\d+"[^>]*>\s*<name[^>]*>\s*free\s*</name>',
        block)]

    # If any free() falls between the two malloc sites, the first is freed — skip
    if any(first_line < fl < second_line for fl in free_lines):
        continue

    # LHS variable name — from first assignment
    var_m = re.search(r'<decl\b[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    varname = var_m.group(1).strip() if var_m else "?"

    second_line_n = second_line
    second_col_n  = int(malloc_calls[1][1])
    first_line_n  = first_line
    first_col_n   = int(malloc_calls[0][1])

    note_msg = f"Original malloc() of '{varname}' at line {first_line_n} — overwritten without free"

    finding = {
        "detector": "overwrite_leak",
        "severity": "warning",
        "rule":     "overwriteLeak",
        "file":     filename,
        "line":     second_line_n,
        "col":      second_col_n,
        "varname":  varname,
        "note": {
            "line":    first_line_n,
            "col":     first_col_n,
            "message": note_msg
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{second_line_n}:{second_col_n} — {varname} overwritten (first alloc at line {first_line_n})")
    found += 1

print(f"[ overwrite_leak ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
