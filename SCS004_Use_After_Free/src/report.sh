#!/usr/bin/env bash
# report.sh <findings.json> <source.c>
#
# Reads all findings written by detectors and emits a cppcheck-style
# report to stdout. Each finding is a JSON object on consecutive lines.
#
# Output format per finding:
#   file:line:col: severity: message [rule] [detector]
#       source line
#
#   file:note_line:note_col: note: message
#       source line
#
# Requires: python3
set -e

FINDINGS=$1
SRC=$2

# -----------------------------------------------------------------------
# Check there is something to report
# -----------------------------------------------------------------------
if [ ! -f "$FINDINGS" ] || [ -z "$(grep -l 'detector' "$FINDINGS" 2>/dev/null)" ]; then
    echo "No findings to report."
    exit 0
fi

# -----------------------------------------------------------------------
# Use Python to parse the JSON findings and emit the report
# Python is used here because the findings file contains multiple
# top-level JSON objects (one per finding, not a JSON array) and
# shell tools cannot reliably parse multi-line JSON
# -----------------------------------------------------------------------
python3 << PYEOF
import json
import sys

findings_file = "$FINDINGS"
src_file = "$SRC"

# Read source lines for display
try:
    with open(src_file) as f:
        src_lines = f.readlines()
except FileNotFoundError:
    src_lines = []

def get_line(n):
    """Return source line at 1-indexed line number n, stripped of newline."""
    if 0 < n <= len(src_lines):
        return src_lines[n - 1].rstrip()
    return ""

# Parse findings — file contains one JSON object per finding,
# not a JSON array, so we parse object by object using a decoder
findings = []
with open(findings_file) as f:
    content = f.read().strip()

# Split on top-level object boundaries — each finding starts with {
# and ends with }. We accumulate characters and decode when balanced.
depth = 0
buf = ""
for ch in content:
    if ch == '{':
        depth += 1
    if depth > 0:
        buf += ch
    if ch == '}':
        depth -= 1
        if depth == 0 and buf.strip():
            try:
                findings.append(json.loads(buf))
            except json.JSONDecodeError:
                pass
            buf = ""

if not findings:
    print("No findings to report.")
    sys.exit(0)

# Sort findings by file then line for consistent output
findings.sort(key=lambda f: (f.get("file",""), f.get("line", 0)))

total = len(findings)
errors   = sum(1 for f in findings if f.get("severity") == "error")
warnings = sum(1 for f in findings if f.get("severity") == "warning")

print(f"{'='*48}")
print(f" CWE-476 Detection Report")
print(f" Source  : {src_file}")
print(f" Findings: {total} ({errors} error(s), {warnings} warning(s))")
print(f"{'='*48}")
print()

for finding in findings:
    ffile    = finding.get("file", "?")
    fline    = finding.get("line", 0)
    fcol     = finding.get("col", 0)
    severity = finding.get("severity", "error")
    rule     = finding.get("rule", "?")
    detector = finding.get("detector", "?")
    varname  = finding.get("varname", "?")
    src_line = finding.get("source_line", get_line(fline))

    # Severity-appropriate message
    if severity == "error":
        msg = f"Null pointer dereference: {varname}"
    else:
        msg = f"Missing null check before dereference: {varname}"

    # Error / warning line
    print(f"{ffile}:{fline}:{fcol}: {severity}: {msg} [{rule}] [{detector}]")
    print(f"    {src_line}")
    print()

    # Note line — declaration site
    note = finding.get("note", {})
    nline = note.get("line", 0)
    ncol  = note.get("col", 0)
    nmsg  = note.get("message", "")
    nsrc  = note.get("source_line", get_line(nline))

    if nline and nmsg:
        print(f"{ffile}:{nline}:{ncol}: note: {nmsg}")
        print(f"    {nsrc}")
        print()

print(f"{'='*48}")
if errors > 0:
    print(f" Result: {errors} error(s) detected")
if warnings > 0:
    print(f" Result: {warnings} warning(s) detected")
if errors == 0 and warnings == 0:
    print(" Result: No smells detected")
print(f"{'='*48}")
PYEOF