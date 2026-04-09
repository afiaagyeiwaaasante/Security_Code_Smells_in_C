#!/usr/bin/env bash
# detectors/detect_signed_memcpy.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 2: signed_memcpy
# Detects: function passes a signed int to memcpy() or memmove() as the byte
#           count with no positivity guard (data > 0) in any <condition>.
# Severity: warning [signedUnsignedConversion]
#
# Strategy:
#   Scan annotated srcML XML for blocks containing memcpy() or memmove() calls.
#   If no <condition> in the block contains &gt; → no positivity guard → finding.
#
#   memmove() is covered here because its detection pattern is identical to
#   memcpy() — both accept a signed value as a size_t count argument.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 2: signed_memcpy ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

echo "    strategy : XML scan — memcpy()/memmove() call with no &gt; guard in <condition>"
echo "--- post-filter: checking for absent positivity guard ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)

MEMCPY_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*(?:memcpy|memmove)\s*</name>'
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

    # Only process blocks that contain memcpy or memmove
    if 'memcpy' not in block and 'memmove' not in block:
        continue

    memcpy_matches = MEMCPY_CALL.findall(block)
    if not memcpy_matches:
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

    # Identify whether it's memcpy or memmove for the message
    sink = "memmove" if "memmove" in block and "memcpy" not in block else "memcpy"

    line = int(memcpy_matches[0][0])
    col  = int(memcpy_matches[0][1])

    note_msg = (f"{sink}() in {fname}() — signed int passed as byte count "
                f"with no positivity guard (data > 0)")

    finding = {
        "detector": "signed_memcpy",
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

    print(f"    finding: {filename}:{line}:{col} — {fname}() {sink} without positivity guard")
    found += 1

print(f"[ signed_memcpy ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
