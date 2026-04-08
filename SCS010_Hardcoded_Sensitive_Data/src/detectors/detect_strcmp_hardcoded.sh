#!/usr/bin/env bash
# detect_strcmp_hardcoded.sh <xml> <src> <findings>
# Detects strcmp()/strncmp() calls where one argument is a string literal,
# indicating a hardcoded password used in an authentication comparison.
# Rule: SCS010-PASSWD-STRCMP
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: strcmp_hardcoded ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

if [ ! -f "$XML" ]; then
    echo "    ERROR: XML file not found: $XML"
    exit 1
fi

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

python3 << PYEOF
import re, json

xml_path      = "$XML"
findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

with open(xml_path) as f:
    content = f.read()

# Match full strcmp/strncmp <call> elements
STRCMP_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*(?:strcmp|strncmp)\s*</name>(.*?)</call>',
    re.DOTALL
)
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
LITERAL_PAT = re.compile(r'<literal\s+type="string"[^>]*>')

for m in STRCMP_CALL.finditer(content):
    line_no = int(m.group(1))
    col_no  = int(m.group(2))
    args_content = m.group(3)
    args = ARG_SPLIT.findall(args_content)

    # Flag if ANY argument is a string literal (hardcoded password in comparison)
    has_literal = any(LITERAL_PAT.search(a) for a in args)
    if not has_literal:
        continue

    # Extract the literal value for the message
    literal_val = ""
    for a in args:
        lm = re.search(r'<literal\s+type="string"[^>]*>([^<]*)</literal>', a)
        if lm:
            literal_val = lm.group(1)
            break

    finding = {
        "detector": "strcmp_hardcoded",
        "severity": "warning",
        "rule":     "SCS010-PASSWD-STRCMP",
        "file":     filename,
        "line":     line_no,
        "col":      col_no,
        "varname":  literal_val,
        "note": {
            "line":    line_no,
            "col":     col_no,
            "message": f"strcmp/strncmp with hardcoded string literal {literal_val!r} — hardcoded credential in comparison"
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{line_no}:{col_no} — strcmp with hardcoded literal {literal_val!r}")
    found += 1

print(f"[ strcmp_hardcoded ] {found} finding(s) written to {findings_path}")
PYEOF

echo
