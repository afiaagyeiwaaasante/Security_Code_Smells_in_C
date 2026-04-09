#!/usr/bin/env bash
# detectors/detect_unchecked_add.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: unchecked_add
# Detects: function contains an addition (+) with no upper-bound guard
#           (INT_MAX / CHAR_MAX / SHRT_MAX / UINT_MAX / INT64_MAX / LLONG_MAX)
#           inside any <condition> element in the same function.
# Severity: warning [integerOverflow]
#
# Strategy:
#   srcQL does not reliably match binary arithmetic patterns like $A + $B.
#   Instead, we read the full annotated srcML XML and search for
#   <operator>+</operator> elements directly.
#
#   Python post-filter:
#     For each function block that contains a + operator:
#     - Extract all <condition>…</condition> sub-elements.
#     - If no condition contains a MAX constant → no upper-bound check → finding.
#
#   Edge case: bad_unsigned_int_add has UINT_MAX as an initialiser value in
#   a <decl>, NOT in a <condition>.  Only counting MAX inside <condition>
#   ensures we don't mistake initialiser use for a guard.
#
#   Position: the <operator>+</operator> element's pos:start attribute.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: unchecked_add ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XML scan — <operator>+</operator> inside function blocks"
echo "--- post-filter: checking for absent MAX guard in <condition> ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

MAX_PATTERN = re.compile(
    r'<name[^>]*>\s*(?:INT_MAX|CHAR_MAX|SHRT_MAX|UINT_MAX|INT64_MAX|LLONG_MAX)\s*</name>'
)
ADD_OP_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\+\s*</operator>'
)

with open("$XML") as f:
    content = f.read()

findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

# Split into per-function/destructor/constructor blocks
func_blocks = re.split(r'(?=<(?:function|destructor|constructor)[\s>])', content)

for block in func_blocks:
    tag_m = re.match(r'<(function|destructor|constructor)', block)
    if not tag_m:
        continue
    tag = tag_m.group(1)

    # Only process blocks that contain a + operator
    add_matches = ADD_OP_PATTERN.findall(block)
    if not add_matches:
        continue

    # Extract all <condition>…</condition> sub-elements
    conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)
    # If any condition contains a MAX constant → bounds check present → skip
    if any(MAX_PATTERN.search(c) for c in conditions):
        continue

    # Also check <if> expression regions for MAX guard (alternate srcML encoding)
    if_exprs = re.findall(
        r'<if\b[^>]*>.*?(?=<block\b|</if>)', block, re.DOTALL)
    if any(MAX_PATTERN.search(e) for e in if_exprs):
        continue

    # Extract function/destructor/constructor name
    if tag == 'function':
        fname_m = re.search(
            r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    # Take the first + occurrence for position
    line = int(add_matches[0][0])
    col  = int(add_matches[0][1])

    note_msg = f"addition in {fname}() — no upper-bound guard before adding"

    finding = {
        "detector": "unchecked_add",
        "severity": "warning",
        "rule":     "integerOverflow",
        "file":     filename,
        "line":     line,
        "col":      col,
        "varname":  fname,
        "note": {
            "line":    line,
            "col":     col,
            "message": note_msg
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{line}:{col} — {fname}() adds without MAX guard")
    found += 1

print(f"[ unchecked_add ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
