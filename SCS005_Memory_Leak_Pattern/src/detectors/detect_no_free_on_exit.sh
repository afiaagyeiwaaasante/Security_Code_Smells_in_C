#!/usr/bin/env bash
# detectors/detect_no_free_on_exit.sh <annotated.xml> <source.c> <findings.json>
#
# Detector 1: no_free_on_exit
# Detects: function allocates with malloc() but never calls free() before
#           returning — the allocated block is permanently leaked.
# Severity: warning [memoryLeak]
#
# Strategy:
#   srcQL query finds every function that contains a malloc() call:
#     FIND $T $FUNC() {} CONTAINS malloc($SIZE)
#
#   XPath post-filter:
#     For each matched function, check if a <name>free</name> call is absent.
#     If absent → the allocation has no paired deallocation → finding.
#
#   Position: pos:start of the malloc() call → finding location.
#   Variable:  LHS identifier of the declaration holding malloc().
#
# Requires: srcml, xmllint, python3

source "$(dirname "$0")/../lib/write_finding.sh"

XML=$1
SRC=$2
FINDINGS=$3

echo "=== Detector 1: no_free_on_exit ==="
echo "    input  : $XML"
echo "    output : $FINDINGS"
echo

TMPRESULT=$(mktemp /tmp/memleak_nofree_XXXXXX)
trap "rm -f $TMPRESULT" EXIT

QUERY='FIND $T $FUNC() {} CONTAINS malloc($SIZE)'
echo "    query  : $QUERY"
{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

if ! grep -q '<function' "$TMPRESULT" 2>/dev/null; then
    echo "    no malloc() calls found — no findings."
    echo
    exit 0
fi

echo "--- post-filter: checking for absent free() ---"

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$TMPRESULT" 2>/dev/null)

# Python parses the srcQL result XML, filters out functions that already call
# free(), and emits one JSON finding per leaked allocation.
FOUND_COUNT=$(python3 << PYEOF
import re, json

with open("$TMPRESULT") as f:
    content = f.read()

findings_path = "$FINDINGS"
filename      = "$FILENAME"
found = 0

# Split the result into one block per <function> element
func_blocks = re.split(r'(?=<function[\s>])', content)

for block in func_blocks:
    if '<function' not in block:
        continue

    # Skip if this function already has a free() call — properly paired
    if re.search(r'<name[^>]*>\s*free\s*</name>', block):
        continue

    # Extract function name
    fname_m = re.search(r'<function[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    fname = fname_m.group(1).strip() if fname_m else "?"

    # Malloc call site — pos:start on the surrounding <call> element
    pos_m = re.search(
        r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*malloc\s*</name>',
        block)
    line = int(pos_m.group(1)) if pos_m else 0
    col  = int(pos_m.group(2)) if pos_m else 0

    # LHS variable name — first <name> inside a <decl> that precedes malloc
    var_m = re.search(
        r'<decl\b[^>]*>.*?<name[^>]*>([^<]+)</name>', block, re.DOTALL)
    varname = var_m.group(1).strip() if var_m else fname

    note_msg = f"malloc() in {fname}() — no free() on any exit path"

    finding = {
        "detector": "no_free_on_exit",
        "severity": "warning",
        "rule":     "memoryLeak",
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

    print(f"    finding: {filename}:{line}:{col} — {varname} (in {fname}(), never freed)")
    found += 1

print(f"[ no_free_on_exit ] {found} finding(s) written to {findings_path}")
PYEOF
)

echo "$FOUND_COUNT"
echo
