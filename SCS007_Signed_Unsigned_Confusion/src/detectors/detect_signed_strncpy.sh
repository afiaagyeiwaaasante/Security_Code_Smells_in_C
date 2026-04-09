#!/usr/bin/env bash
# detectors/detect_signed_strncpy.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: signed_strncpy
# Detects: function passes a signed int to strncpy() as the character count
#           with no positivity guard (data > 0) in any <condition>.
# Severity: warning [signedUnsignedConversion]
#
# Strategy:
#   Scan annotated srcML XML for blocks containing strncpy() calls.
#   If no <condition> in the block contains &gt; → no positivity guard → finding.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: signed_strncpy ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XML scan — strncpy() call with no &gt; guard in <condition>"
echo "--- post-filter: checking for absent positivity guard ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)

STRNCPY_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*strncpy\s*</name>'
)

with open("$XML") as f:
    content = f.read()

findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

func_blocks = re.split(r'(?=<(?:function|destructor|constructor)[\s>])', content)

for block in func_blocks:
    tag_m = re.match(r'<(function|destructor|constructor)', block)
    if not tag_m:
        continue
    tag = tag_m.group(1)

    # Only process blocks that contain strncpy
    if 'strncpy' not in block:
        continue

    strncpy_matches = STRNCPY_CALL.findall(block)
    if not strncpy_matches:
        continue

    # Extract all <condition> elements
    conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)

    # If any condition contains &gt; → positivity guard present → skip
    if any(POSITIVE_GUARD.search(c) for c in conditions):
        continue

    # Extract function name
    if tag == 'function':
        fname_m = re.search(
            r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    line = int(strncpy_matches[0][0])
    col  = int(strncpy_matches[0][1])

    note_msg = (f"strncpy() in {fname}() — signed int passed as char count "
                f"with no positivity guard (data > 0)")

    finding = {
        "detector": "signed_strncpy",
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

    print(f"    finding: {filename}:{line}:{col} — {fname}() strncpy without positivity guard")
    found += 1

print(f"[ signed_strncpy ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
