#!/usr/bin/env bash
# detect_password_literal.sh <xml> <src> <findings>
# Detects variable declarations or assignments where:
#   - the variable name matches a credential keyword (password, passwd, pwd,
#     secret, key, token, api_key, credential, passphrase), AND
#   - the value is a string literal (not read from input).
# Rule: SCS010-PASSWD-VAR
set -e

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector: password_literal ==="
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

# Credential keyword pattern — matches anywhere in the identifier name
# (no \b so that password_, _password, m_password all match)
CRED_NAME = re.compile(
    r'(?i)(?:password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)'
)

DECL_FULL     = re.compile(r'<decl\b[^>]*pos:start="(\d+):(\d+)"[^>]*>(.*?)</decl>', re.DOTALL)
DECL_NAME_PAT = re.compile(r'<name[^>]*>([^<]+)</name>')
LITERAL_PAT   = re.compile(r'<literal\s+type="string"[^>]*>')
INIT_PAT      = re.compile(r'<init\b[^>]*>(.*?)</init>', re.DOTALL)

# Pattern 1: <decl> with credential name and direct string literal init
for m in DECL_FULL.finditer(content):
    line_no   = int(m.group(1))
    col_no    = int(m.group(2))
    decl_body = m.group(3)

    init_m = INIT_PAT.search(decl_body)
    if not init_m:
        continue
    init_content = init_m.group(1)

    # Skip if the init value is a function call (e.g. getenv("KEY"), strdup(...))
    if '<call' in init_content:
        continue

    if not LITERAL_PAT.search(init_content):
        continue

    # Skip empty string literals — "" is a buffer initialiser, not a credential
    lit_m = re.search(r'<literal\s+type="string"[^>]*>([^<]*)</literal>', init_content)
    if lit_m and lit_m.group(1).strip() in ('""', "''"):
        continue

    names = DECL_NAME_PAT.findall(decl_body)
    cred_name = next((n.strip() for n in names if CRED_NAME.search(n)), None)
    if not cred_name:
        continue

    finding = {
        "detector": "password_literal",
        "severity": "warning",
        "rule":     "SCS010-PASSWD-VAR",
        "file":     filename,
        "line":     line_no,
        "col":      col_no,
        "varname":  cred_name,
        "note": {
            "line":    line_no,
            "col":     col_no,
            "message": f"Variable '{cred_name}' initialised to a string literal — hardcoded sensitive data"
        }
    }
    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")
    print(f"    finding: {filename}:{line_no}:{col_no} — '{cred_name}' initialised to string literal")
    found += 1

# Pattern 2: strcpy(credential_var, "literal") — hardcoded password copied into named buffer
STRCPY_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*strcpy\s*</name>(.*?)</call>',
    re.DOTALL
)
ARG_SPLIT = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)

for m in STRCPY_CALL.finditer(content):
    line_no      = int(m.group(1))
    col_no       = int(m.group(2))
    args_content = m.group(3)
    args = ARG_SPLIT.findall(args_content)
    if len(args) < 2:
        continue

    # First arg must contain a credential-named variable
    first_names = DECL_NAME_PAT.findall(args[0])
    cred_name = next((n.strip() for n in first_names if CRED_NAME.search(n)), None)
    if not cred_name:
        continue

    # Second arg must be a string literal
    if not LITERAL_PAT.search(args[1]):
        continue

    finding = {
        "detector": "password_literal",
        "severity": "warning",
        "rule":     "SCS010-PASSWD-VAR",
        "file":     filename,
        "line":     line_no,
        "col":      col_no,
        "varname":  cred_name,
        "note": {
            "line":    line_no,
            "col":     col_no,
            "message": f"strcpy into '{cred_name}' from a string literal — hardcoded sensitive data"
        }
    }
    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")
    print(f"    finding: {filename}:{line_no}:{col_no} — strcpy into '{cred_name}' from literal")
    found += 1

print(f"[ password_literal ] {found} finding(s) written to {findings_path}")
PYEOF

echo
