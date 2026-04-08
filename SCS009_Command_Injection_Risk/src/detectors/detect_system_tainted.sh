#!/usr/bin/env bash
# detect_system_tainted.sh <xml> <src> <findings>
# Detects system() calls in blocks that also contain a user-input source
# (fgets or getenv) — indicating tainted data flows into the OS command.
# Guard: no fgets/getenv call in the same block as system().
# Rule: SCS009-SYSTEM
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: system_tainted ==="
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

# Match the full <call>...</call> element for system()
SYSTEM_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*system\s*</name>(.*?)</call>',
    re.DOTALL
)
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
LITERAL_PAT = re.compile(r'<literal\b')
INPUT_SOURCE = re.compile(
    r'<name[^>]*>\s*(?:fgets|getenv)\s*</name>'
)

func_blocks = re.split(r'(?=<(?:function|destructor|constructor)[\s>])', content)

for block in func_blocks:
    tag_m = re.match(r'<(function|destructor|constructor)', block)
    if not tag_m:
        continue

    # Guard: block must contain a user-input source
    if not INPUT_SOURCE.search(block):
        continue  # no taint source — goodG2B pattern, skip

    first_match = None
    for m in SYSTEM_CALL.finditer(block):
        line_no = int(m.group(1))
        col_no  = int(m.group(2))
        args_content = m.group(3)
        args = ARG_SPLIT.findall(args_content)
        if not args:
            continue
        # Skip if first argument is a string literal (safe call)
        if LITERAL_PAT.search(args[0]):
            continue
        first_match = (line_no, col_no)
        break

    if first_match is None:
        continue

    line, col = first_match

    tag = tag_m.group(1)
    if tag == 'function':
        fname_m = re.search(r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    finding = {
        "detector": "system_tainted",
        "severity": "warning",
        "rule":     "SCS009-SYSTEM",
        "file":     filename,
        "line":     line,
        "col":      col,
        "varname":  fname,
        "note": {
            "line":    line,
            "col":     col,
            "message": f"system() in {fname}() — user input source (fgets/getenv) in same block; data may contain shell metacharacters"
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{line}:{col} — {fname}() system() with tainted input")
    found += 1

print(f"[ system_tainted ] {found} finding(s) written to {findings_path}")
PYEOF

echo
