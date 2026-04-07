#!/usr/bin/env bash
# detect_syslog_direct.sh <xml> <src> <findings>
# Detects syslog calls where the second argument (format) is a variable.
# syslog(priority, format, ...) — format is argument index 1.
# Guard: second argument contains a <literal> element.
# Rule: SCS008-SYSLOG
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: syslog_direct ==="
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

SYSLOG_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*syslog\s*</name>'
)
LITERAL_PAT = re.compile(r'<literal\b')
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)

func_blocks = re.split(r'(?=<(?:function|destructor|constructor)[\s>])', content)

for block in func_blocks:
    tag_m = re.match(r'<(function|destructor|constructor)', block)
    if not tag_m:
        continue

    if not SYSLOG_CALL.search(block):
        continue

    tag = tag_m.group(1)
    if tag == 'function':
        fname_m = re.search(r'<function[^>]*>.*?</type>\s*<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    else:
        fname_m = re.search(r'<name[^>]*>([^<]+)</name>', block)
    fname = fname_m.group(1).strip() if fname_m else "?"

    for call_m in re.finditer(r'<call\b[^>]*>(.*?)</call>', block, re.DOTALL):
        call_text = call_m.group(0)
        if not re.search(r'<name[^>]*>\s*syslog\s*</name>', call_text):
            continue

        # syslog(priority, format, ...) — format is second argument (index 1)
        arglist_m = re.search(r'<argument_list\b[^>]*>(.*?)</argument_list>', call_text, re.DOTALL)
        if not arglist_m:
            continue
        args = ARG_SPLIT.findall(arglist_m.group(1))
        if len(args) < 2:
            continue
        if LITERAL_PAT.search(args[1]):
            continue  # guarded

        pos_m = re.search(r'<call\b[^>]*pos:start="(\d+):(\d+)"', call_text)
        line = int(pos_m.group(1)) if pos_m else 0
        col  = int(pos_m.group(2)) if pos_m else 0

        finding = {
            "detector": "syslog_direct",
            "severity": "warning",
            "rule":     "SCS008-SYSLOG",
            "file":     filename,
            "line":     line,
            "col":      col,
            "varname":  fname,
            "note": {
                "line":    line,
                "col":     col,
                "message": f"syslog in {fname}() — variable used directly as format argument (no literal format specifier)"
            }
        }

        with open(findings_path, "a") as fp:
            fp.write(json.dumps(finding, indent=2) + "\n")

        print(f"    finding: {filename}:{line}:{col} — {fname}() syslog without literal format specifier")
        found += 1
        break

print(f"[ syslog_direct ] {found} finding(s) written to {findings_path}")
PYEOF

echo
