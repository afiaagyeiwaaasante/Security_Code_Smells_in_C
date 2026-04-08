#!/usr/bin/env bash
# detect_define_credential.sh <xml> <src> <findings>
# Detects preprocessor #define macros where:
#   - the macro name matches a credential keyword (PASSWORD, SECRET, API_KEY, etc.)
#   - the value is a quoted string literal
# Rule: SCS010-PASSWD-DEFINE
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: define_credential ==="
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

# Credential keyword pattern for macro names (no \b — PASSWORD_, _SECRET, etc. all match)
CRED_NAME = re.compile(
    r'(?i)(?:password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)'
)

# Match full <cpp:define> elements
DEFINE_FULL = re.compile(
    r'<cpp:define\b[^>]*pos:start="(\d+):(\d+)"[^>]*>(.*?)</cpp:define>',
    re.DOTALL
)
MACRO_NAME_PAT = re.compile(r'<cpp:macro\b[^>]*>\s*<name[^>]*>([^<]+)</name>')
VALUE_PAT      = re.compile(r'<cpp:value[^>]*>([^<]*)</cpp:value>')
QUOTED_PAT     = re.compile(r'^"[^"]*"$')

for m in DEFINE_FULL.finditer(content):
    line_no = int(m.group(1))
    col_no  = int(m.group(2))
    define_body = m.group(3)

    # Macro name must match credential keyword
    name_m = MACRO_NAME_PAT.search(define_body)
    if not name_m:
        continue
    macro_name = name_m.group(1).strip()
    if not CRED_NAME.search(macro_name):
        continue

    # Value must be a quoted string literal
    val_m = VALUE_PAT.search(define_body)
    if not val_m:
        continue
    val = val_m.group(1).strip()
    if not QUOTED_PAT.match(val):
        continue

    finding = {
        "detector": "define_credential",
        "severity": "warning",
        "rule":     "SCS010-PASSWD-DEFINE",
        "file":     filename,
        "line":     line_no,
        "col":      col_no,
        "varname":  macro_name,
        "note": {
            "line":    line_no,
            "col":     col_no,
            "message": f"#define '{macro_name}' set to a string literal — hardcoded credential in preprocessor macro"
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{line_no}:{col_no} — #define '{macro_name}' = {val}")
    found += 1

print(f"[ define_credential ] {found} finding(s) written to {findings_path}")
PYEOF

echo
