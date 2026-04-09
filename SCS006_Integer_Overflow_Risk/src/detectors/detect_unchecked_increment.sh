#!/usr/bin/env bash
# detectors/detect_unchecked_increment.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: unchecked_increment
# Detects: function contains a ++ (postfix or prefix increment) with no
#           upper-bound guard (INT_MAX / CHAR_MAX / SHRT_MAX / UINT_MAX /
#           INT64_MAX / LLONG_MAX) inside any <condition> element.
# Severity: warning [integerOverflow]
#
# Strategy:
#   srcQL does not have a built-in pattern for ++ operators.
#   Instead, srcML annotates the source into XML and we use xmllint XPath
#   to find functions that contain <operator>++</operator> (covers both
#   prefix `++x` and postfix `x++`).
#
#   Python post-filter:
#     For each matched function block, check all <condition> elements for a
#     MAX constant.  If absent → no bound check → finding.
#
#   Position: pos:start on the <operator>++</operator> element.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: unchecked_increment ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

TMPRESULT=$(mktemp /tmp/intover_inc_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

echo "    strategy : XPath — <operator>++</operator> inside function blocks"

# Use xmllint to dump the full srcML unit, then post-process in Python.
# We pass the entire XML to Python and do all filtering there.
cp "$XML" "$TMPRESULT"

echo "--- post-filter: extracting ++ usages, checking for absent MAX guard ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

MAX_PATTERN = re.compile(
    r'<name[^>]*>\s*(?:INT_MAX|CHAR_MAX|SHRT_MAX|UINT_MAX|INT64_MAX|LLONG_MAX)\s*</name>'
)
INC_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\+\+\s*</operator>'
)

with open("$TMPRESULT") as f:
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

    # Only process blocks that actually contain ++
    if '++' not in block:
        continue

    # Find ++ operator elements
    inc_matches = INC_PATTERN.findall(block)
    if not inc_matches:
        continue

    # Extract all <condition>…</condition> sub-elements
    conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)
    # If any condition contains a MAX constant → guarded → skip
    if any(MAX_PATTERN.search(c) for c in conditions):
        continue

    # Also check <if> expression regions for MAX guard
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

    # Take the first ++ occurrence for position
    line = int(inc_matches[0][0])
    col  = int(inc_matches[0][1])

    note_msg = f"increment (++) in {fname}() — no upper-bound guard (INT_MAX check)"

    finding = {
        "detector": "unchecked_increment",
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

    print(f"    finding: {filename}:{line}:{col} — {fname}() increments without MAX guard")
    found += 1

print(f"[ unchecked_increment ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
