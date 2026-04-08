#!/usr/bin/env bash
# report.sh <findings.json> <source.c>
# Reads all findings and emits a cppcheck-style report to stdout.
set -e

FINDINGS=$1
SRC=$2

if [ ! -f "$FINDINGS" ] || [ -z "$(grep -l 'detector' "$FINDINGS" 2>/dev/null)" ]; then
    echo "No findings to report."
    exit 0
fi

python3 << PYEOF
import json, sys

findings_file = "$FINDINGS"
src_file      = "$SRC"

try:
    with open(src_file) as f:
        src_lines = f.readlines()
except FileNotFoundError:
    src_lines = []

def get_line(n):
    if 0 < n <= len(src_lines):
        return src_lines[n - 1].rstrip()
    return ""

findings = []
with open(findings_file) as f:
    content = f.read().strip()

depth, buf = 0, ""
for ch in content:
    if ch == '{': depth += 1
    if depth > 0: buf += ch
    if ch == '}':
        depth -= 1
        if depth == 0 and buf.strip():
            try: findings.append(json.loads(buf))
            except json.JSONDecodeError: pass
            buf = ""

if not findings:
    print("No findings to report.")
    sys.exit(0)

findings.sort(key=lambda f: (f.get("file",""), f.get("line", 0)))

total    = len(findings)
errors   = sum(1 for f in findings if f.get("severity") == "error")
warnings = sum(1 for f in findings if f.get("severity") == "warning")

print(f"{'='*52}")
print(f" CWE-259 Hardcoded Sensitive Data Report")
print(f" Source  : {src_file}")
print(f" Findings: {total} ({errors} error(s), {warnings} warning(s))")
print(f"{'='*52}")
print()

DETECTOR_MSGS = {
    "password_literal":  "Credential variable initialised to string literal — hardcoded sensitive data",
    "define_credential": "#define macro for credential set to string literal — hardcoded sensitive data",
    "strcmp_hardcoded":  "strcmp/strncmp called with hardcoded string literal — hardcoded password comparison",
}

for finding in findings:
    ffile    = finding.get("file", "?")
    fline    = finding.get("line", 0)
    fcol     = finding.get("col", 0)
    severity = finding.get("severity", "warning")
    rule     = finding.get("rule", "?")
    detector = finding.get("detector", "?")
    src_line = finding.get("source_line", get_line(fline))

    msg = DETECTOR_MSGS.get(detector, "Hardcoded sensitive data")

    print(f"{ffile}:{fline}:{fcol}: {severity}: {msg} [{rule}] [{detector}]")
    print(f"    {src_line}")
    print()

    note = finding.get("note", {})
    nline = note.get("line", 0)
    nmsg  = note.get("message", "")
    nsrc  = note.get("source_line", get_line(nline))
    if nline and nmsg:
        print(f"{ffile}:{nline}:{note.get('col',0)}: note: {nmsg}")
        print(f"    {nsrc}")
        print()

print(f"{'='*52}")
if warnings > 0:
    print(f" Result: {warnings} warning(s) detected")
if errors > 0:
    print(f" Result: {errors} error(s) detected")
if errors == 0 and warnings == 0:
    print(" Result: No smells detected")
print(f"{'='*52}")
PYEOF
