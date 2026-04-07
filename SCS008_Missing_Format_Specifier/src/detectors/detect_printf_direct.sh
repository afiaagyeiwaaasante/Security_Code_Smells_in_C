#!/usr/bin/env bash
# detect_printf_direct.sh <xml> <src> <findings>
# Detects printf/vprintf calls where the first argument is a variable, not a string literal.
# Guard: first argument contains a <literal> element (e.g. "%s", "%d\n").
# Rule: SCS008-PRINTF
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: printf_direct ==="
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

# Find printf/vprintf call positions — capture pos:start from the <call> tag
PRINTF_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*(?:printf|vprintf)\s*</name>'
)
LITERAL_PAT = re.compile(r'<literal\b')
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)

func_blocks = re.split(r'(?=<(?:function|destructor|constructor)[\s>])', content)

for block in func_blocks:
    tag_m = re.match(r'<(function|destructor|constructor)', block)
    if not tag_m:
        continue

    if not PRINTF_CALL.search(block):
        continue

    tag = tag_m.group(1)
    if tag == 'function':
        fname_m = re.search(r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    # Find each printf/vprintf call in this block
    for call_m in re.finditer(r'<call\b[^>]*>(.*?)</call>', block, re.DOTALL):
        call_text = call_m.group(0)
        if not re.search(r'<name[^>]*>\s*(?:printf|vprintf)\s*</name>', call_text):
            continue

        # Extract first argument — must NOT be a string literal
        arglist_m = re.search(r'<argument_list\b[^>]*>(.*?)</argument_list>', call_text, re.DOTALL)
        if not arglist_m:
            continue
        args = ARG_SPLIT.findall(arglist_m.group(1))
        if not args:
            continue
        if LITERAL_PAT.search(args[0]):
            continue  # guarded — first arg is a literal format string

        # Get position from <call pos:start="line:col">
        pos_m = re.search(r'<call\b[^>]*pos:start="(\d+):(\d+)"', call_text)
        line = int(pos_m.group(1)) if pos_m else 0
        col  = int(pos_m.group(2)) if pos_m else 0

        finding = {
            "detector": "printf_direct",
            "severity": "warning",
            "rule":     "SCS008-PRINTF",
            "file":     filename,
            "line":     line,
            "col":      col,
            "varname":  fname,
            "note": {
                "line":    line,
                "col":     col,
                "message": f"printf/vprintf in {fname}() — variable used directly as format argument (no literal format specifier)"
            }
        }

        with open(findings_path, "a") as fp:
            fp.write(json.dumps(finding, indent=2) + "\n")

        print(f"    finding: {filename}:{line}:{col} — {fname}() printf without literal format specifier")
        found += 1
        break  # one finding per function block

print(f"[ printf_direct ] {found} finding(s) written to {findings_path}")
PYEOF

echo
