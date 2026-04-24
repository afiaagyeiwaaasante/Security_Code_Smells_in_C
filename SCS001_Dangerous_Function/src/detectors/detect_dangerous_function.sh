#!/usr/bin/env bash
# SCS001 — detect_dangerous_function.sh
# Detects calls to inherently dangerous C functions (CWE-242, CWE-120).
#
# Usage:
#   bash detect_dangerous_function.sh <annotated.xml> <source.c> <findings.json>
#
# Pipeline:
#   1. Build a srcQL UNION query covering all dangerous functions
#   2. Run srcql against the annotated XML
#   3. Extract call-site positions via XPath (xmllint)
#   4. Build one JSON finding per call site (Python)
#
# Known limitations:
#   - Macro-wrapped calls: srcML parses pre-expansion text; the call node
#     name is the macro name, not the function name. Not matched.
#   - Function pointer aliases: the call node name is the pointer variable.
#     Not matched by name-based srcQL.
set -e

XML="$1"
SRC="$2"
FINDINGS_OUT="$3"

echo "=== Detector 1: dangerous_function ==="
echo "    input  : $XML"
echo "    output : $FINDINGS_OUT"
echo

# -----------------------------------------------------------------------
# Dangerous function catalogue
# Parallel arrays — portable on bash 3 (macOS) and bash 4+.
# Each index position ties together: function name, safe alternative,
# and the human-readable note emitted in the finding.
# -----------------------------------------------------------------------
FUNC_NAMES=(   "gets"     "strcpy"                        "strcat"                            "sprintf"                        "vsprintf"                          "scanf"                                    "sscanf"                              )
FUNC_ALTS=(    "fgets(\$dest, size, stdin)"
               "strncpy(\$dst, \$src, n) or strlcpy"
               "strncat(\$dst, \$src, remaining)"
               "snprintf(\$buf, size, \$fmt, ...)"
               "vsnprintf(\$buf, size, \$fmt, \$ap)"
               "scanf with explicit field width (e.g. \"%Ns\")"
               "sscanf with explicit field width"             )
FUNC_PARAMS=(  "\$DEST"
               "\$DST, \$SRC"
               "\$DST, \$SRC"
               "\$BUF, \$FMT"
               "\$BUF, \$FMT, \$AP"
               "\$FMT, \$BUF"
               "\$STR, \$FMT, \$BUF"                         )

# -----------------------------------------------------------------------
# Stage 2: build the srcQL UNION query from the catalogue
# -----------------------------------------------------------------------
QUERY=""
for i in "${!FUNC_NAMES[@]}"; do
    FUNC="${FUNC_NAMES[$i]}"
    PARAMS="${FUNC_PARAMS[$i]}"
    PART="FIND \$T \$FUNC(\$PARAMS) {} CONTAINS ${FUNC}(${PARAMS})"
    if [ -z "$QUERY" ]; then
        QUERY="$PART"
    else
        QUERY="$QUERY UNION $PART"
    fi
done

echo "    query  : $QUERY"
echo

# Run srcql; capture the result XML in a temp file
TMPRESULT=$(mktemp /tmp/srcql_result_XXXXXX.xml)
trap "rm -f $TMPRESULT" EXIT

{ time srcml "$XML" --srcql "$QUERY" -q > "$TMPRESULT"; } 2>&1
echo

# -----------------------------------------------------------------------
# Stage 3: extract positions and build findings
# -----------------------------------------------------------------------
echo "--- extracting positions ---"
echo "--- building findings ---"

> "$FINDINGS_OUT"

python3 - "$TMPRESULT" "$XML" "$FINDINGS_OUT" \
    "${FUNC_NAMES[@]}" \
    << 'PYEOF'
import sys
import re
import json

result_xml  = sys.argv[1]   # srcql output XML (matched function bodies)
source_xml  = sys.argv[2]   # original annotated XML (for filename lookup)
findings_out = sys.argv[3]
# remaining args: the function names from the catalogue
func_names  = sys.argv[4:]

# Read the srcql result XML as plain text; use regex to extract:
#   - The filename from the enclosing <unit filename="..."> attribute
#   - Every <call pos:start="LINE:COL"><name>FUNC</name>... occurrence
#   - The first argument name inside <argument_list><argument><expr><name>

content = open(result_xml).read()

# Filename: take from the first unit/@filename in the result, or fall back
# to the source XML filename attribute
filename = "?"
fn_match = re.search(r'<unit[^>]+filename="([^"]+)"', content)
if fn_match:
    filename = fn_match.group(1)
else:
    src_content = open(source_xml).read()
    fn_match2 = re.search(r'<unit[^>]+filename="([^"]+)"', src_content)
    if fn_match2:
        filename = fn_match2.group(1)

# Pattern: <call pos:start="L:C"...><name ...>FUNCNAME</name>...<argument_list>(<argument><expr><name>VAR</name>
CALL_PAT = re.compile(
    r'<call[^>]+pos:start="(\d+):(\d+)"[^>]*>'   # call element with position
    r'(?:.*?)'                                     # anything between call and name
    r'<name[^>]*>([^<]+)</name>',                  # function name
    re.DOTALL
)

# For each matched call that names a dangerous function, extract varname from
# the first argument
ARG_PAT = re.compile(
    r'<argument_list[^>]*>\('                      # opening of argument list
    r'.*?<argument[^>]*>.*?<expr[^>]*>.*?<name[^>]*>([^<]+)</name>',
    re.DOTALL
)

findings = []
finding_num = 0

for call_match in CALL_PAT.finditer(content):
    line_str, col_str, called_name = call_match.groups()
    called_name = called_name.strip()

    if called_name not in func_names:
        continue

    line = int(line_str)
    col  = int(col_str)

    # Extract the call body up to </call> for argument inspection
    call_start = call_match.start()
    call_end   = content.find('</call>', call_start)
    call_body  = content[call_start:call_end] if call_end != -1 else content[call_start:]

    # For scanf/sscanf: only flag if the format string literal contains a
    # bare %s with no explicit width. A bounded specifier like %9s is safe.
    # If the format is a macro/variable (no literal node), flag conservatively.
    if called_name in ("scanf", "sscanf"):
        fmt_lit = re.search(
            r'<argument_list[^>]*>\(.*?<argument[^>]*>.*?<literal[^>]*type="string"[^>]*>([^<]+)</literal>',
            call_body, re.DOTALL
        )
        if fmt_lit:
            fmt_val = fmt_lit.group(1)
            if re.search(r'%\d+s', fmt_val):
                continue  # explicit width — safe, skip

    varname = "?"
    arg_match = ARG_PAT.search(call_body)
    if arg_match:
        varname = arg_match.group(1).strip()

    # Safe alternative message per function
    alt_map = {
        "gets":     f"use fgets({varname}, size, stdin) instead",
        "strcpy":   f"use strncpy({varname}, src, n) or strlcpy instead",
        "strcat":   f"use strncat({varname}, src, remaining) instead",
        "sprintf":  f"use snprintf({varname}, size, fmt, ...) instead",
        "vsprintf": f"use vsnprintf({varname}, size, fmt, ap) instead",
        "scanf":    f"use scanf with explicit field width (e.g. \"%Ns\") instead",
        "sscanf":   f"use sscanf with explicit field width instead",
    }
    message = (f"{called_name}() is inherently dangerous — "
               + alt_map.get(called_name, "use the bounded safe alternative"))

    finding_num += 1
    print(f"    finding {finding_num}: {filename}:{line}:{col} — {called_name}({varname})")

    finding = {
        "detector":        "dangerous_function",
        "severity":        "error",
        "classification":  "vulnerability",
        "rule":            "dangerousFunction",
        "file":            filename,
        "line":            line,
        "col":             col,
        "varname":         varname,
        "note": {
            "line":    line,
            "col":     col,
            "message": message,
        }
    }
    findings.append(finding)

with open(findings_out, "w") as f:
    for finding in findings:
        f.write(json.dumps(finding, indent=2) + "\n")

print()
print(f"[ dangerous_function ] {len(findings)} finding(s) written to {findings_out}")
PYEOF