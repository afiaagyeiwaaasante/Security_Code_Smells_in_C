#!/usr/bin/env bash
# detectors/detect_signed_malloc.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: signed_malloc
# Detects: function passes a signed int to malloc() with no positivity guard
#           (data > 0 or data >= 1) in any <condition> in the same block.
# Severity: warning [signedUnsignedConversion]
#
# Strategy:
#   Scan the annotated srcML XML for function/destructor/constructor blocks
#   that contain a malloc() call.
#
#   Python post-filter:
#     For each such block, extract all <condition> sub-elements.
#     If no condition contains a &gt; operator (lower-bound check) → the
#     signed value is passed to malloc() without a positivity guard → finding.
#
#   Discriminating pattern:
#     Bad:  conditions only contain &lt; (upper bound, e.g. data < 100)
#     Good: conditions also contain &gt; (lower bound, e.g. data > 0)
#
#   Position: pos:start on the <call><name>malloc</name>... element.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: signed_malloc ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XML scan — malloc() call with no &gt; guard in <condition>"
echo "--- post-filter: checking for absent positivity guard ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

# A positivity guard: any &gt; or &gt;= operator inside a <condition>
POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)

MALLOC_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*malloc\s*</name>'
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

    # Only process blocks that contain malloc()
    if 'malloc' not in block:
        continue

    malloc_matches = MALLOC_CALL.findall(block)
    if not malloc_matches:
        continue

    # Extract all <condition> elements in this block
    conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)

    # If any condition contains &gt; (>) → positivity guard present → skip
    if any(POSITIVE_GUARD.search(c) for c in conditions):
        continue

    # Extract function/destructor/constructor name
    if tag == 'function':
        fname_m = re.search(
            r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    line = int(malloc_matches[0][0])
    col  = int(malloc_matches[0][1])

    note_msg = (f"malloc() in {fname}() — signed int passed as size "
                f"with no positivity guard (data > 0)")

    finding = {
        "detector": "signed_malloc",
        "severity": "warning",
        "rule":     "signedUnsignedConversion",
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

    print(f"    finding: {filename}:{line}:{col} — {fname}() malloc without positivity guard")
    found += 1

print(f"[ signed_malloc ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
