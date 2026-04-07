#!/usr/bin/env bash
# detectors/detect_new_no_delete.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 3: new_no_delete
# Detects: C++ object allocated with new but delete is never called before
#           the pointer goes out of scope.
# Severity: warning [newNoDelete]
#
# Strategy:
#   srcQL query finds every function that contains a new expression:
#     FIND $T $FUNC() {} CONTAINS new $TYPE()
#
#   XPath post-filter:
#     If the matched function contains no <operator>.delete call, emit finding.
#
#   Position: pos:start of the new expression → finding location.
#   Variable:  LHS identifier of the declaration holding the new expression.
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 3: new_no_delete ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

TMPRESULT=$(mktemp /tmp/memleak_newdel_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

QUERY='FIND $T $FUNC() {} CONTAINS new $TYPE()'
echo "    query  : $QUERY"
{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "    no new expressions found — no findings."
    echo
    exit 0
fi

echo "--- post-filter: checking for absent delete ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

FOUND_COUNT=$(python3 << PYEOF
import re, json

with open("$TMPRESULT") as f:
    content = f.read()

findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

func_blocks = re.split(r'(?=<function[\s>])', content)

for block in func_blocks:
    if '<function' not in block:
        continue

    # Skip if this function already has a delete call.
    # srcML represents 'delete ptr;' as <operator>delete</operator>
    if re.search(r'<operator[^>]*>\s*delete\s*</operator>|<name[^>]*>\s*delete\s*</name>|<delete\b', block):
        continue

    fname_m = re.search(r'<function[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    fname = fname_m.group(1).strip() if fname_m else "?"

    # new expression position
    pos_m = re.search(r'<new\b[^>]*pos:start="(\d+):(\d+)"', block)
    if not pos_m:
        # Try operator new
        pos_m = re.search(r'pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*new\s*</name>', block)
    line = int(pos_m.group(1)) if pos_m else 0
    col  = int(pos_m.group(2)) if pos_m else 0

    # LHS variable name
    var_m = re.search(r'<decl\b[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    varname = var_m.group(1).strip() if var_m else fname

    note_msg = f"new in {fname}() — no delete on any exit path"

    finding = {
        "detector": "new_no_delete",
        "severity": "warning",
        "rule":     "newNoDelete",
        "file":     filename,
        "line":     line,
        "col":      col,
        "varname":  varname,
        "note": {
            "line":    line,
            "col":     col,
            "message": note_msg
        }
    }

    with open(findings_path, "a") as fp:
        fp.write(json.dumps(finding, indent=2) + "\n")

    print(f"    finding: {filename}:{line}:{col} — {varname} (in {fname}(), never deleted)")
    found += 1

print(f"[ new_no_delete ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
