#!/usr/bin/env bash
# src/lib/write_finding.sh
#
# Shared utility — write one finding to the findings JSON file.
# Source this file in each detector script:
#   source "$(dirname "$0")/../lib/write_finding.sh"
#
# Usage:
#   write_finding \
#     --findings  <path>      REQUIRED: findings output file
#     --detector  <name>      REQUIRED: binary_if | interprocedural | null_deref | missing_guard
#     --severity  <level>     REQUIRED: error | warning
#     --rule      <id>        REQUIRED: nullPointer | missingNullCheck
#     --file      <path>      REQUIRED: source file path
#     --line      <n>         REQUIRED: line number of finding
#     --col       <n>         REQUIRED: column number of finding
#     --varname   <name>      REQUIRED: variable name involved
#     --note-line <n>         OPTIONAL: line number of note
#     --note-col  <n>         OPTIONAL: column of note
#     --note-msg  <text>      OPTIONAL: note message

write_finding() {
    local FINDINGS="" DETECTOR="" SEVERITY="" RULE=""
    local FILE="" LINE="" COL="" VARNAME=""
    local NOTE_LINE="" NOTE_COL="" NOTE_MSG=""

    # Parse named arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --findings)  FINDINGS="$2";  shift 2 ;;
            --detector)  DETECTOR="$2";  shift 2 ;;
            --severity)  SEVERITY="$2";  shift 2 ;;
            --rule)      RULE="$2";      shift 2 ;;
            --file)      FILE="$2";      shift 2 ;;
            --line)      LINE="$2";      shift 2 ;;
            --col)       COL="$2";       shift 2 ;;
            --varname)   VARNAME="$2";   shift 2 ;;
            --note-line) NOTE_LINE="$2"; shift 2 ;;
            --note-col)  NOTE_COL="$2";  shift 2 ;;
            --note-msg)  NOTE_MSG="$2";  shift 2 ;;
            *) echo "write_finding: unknown argument $1" >&2; return 1 ;;
        esac
    done

    # Validate required fields — explicit checks, no indirect expansion
    if [ -z "$FINDINGS" ];  then echo "write_finding: missing --findings"  >&2; return 1; fi
    if [ -z "$DETECTOR" ];  then echo "write_finding: missing --detector"  >&2; return 1; fi
    if [ -z "$SEVERITY" ];  then echo "write_finding: missing --severity"  >&2; return 1; fi
    if [ -z "$RULE" ];      then echo "write_finding: missing --rule"      >&2; return 1; fi
    if [ -z "$FILE" ];      then echo "write_finding: missing --file"      >&2; return 1; fi
    if [ -z "$LINE" ];      then echo "write_finding: missing --line"      >&2; return 1; fi
    if [ -z "$COL" ];       then echo "write_finding: missing --col"       >&2; return 1; fi
    if [ -z "$VARNAME" ];   then echo "write_finding: missing --varname"   >&2; return 1; fi

    # Escape values for JSON
    local FILE_ESC VARNAME_ESC NOTE_MSG_ESC
    FILE_ESC=$(echo "$FILE"       | sed 's/\\/\\\\/g; s/"/\\"/g')
    VARNAME_ESC=$(echo "$VARNAME" | sed 's/\\/\\\\/g; s/"/\\"/g')
    NOTE_MSG_ESC=$(echo "$NOTE_MSG" | sed 's/\\/\\\\/g; s/"/\\"/g')

    # Write finding — with or without note block
    if [ -n "$NOTE_LINE" ] && [ -n "$NOTE_MSG" ]; then
        cat >> "$FINDINGS" << EOF
{
  "detector": "${DETECTOR}",
  "severity": "${SEVERITY}",
  "rule": "${RULE}",
  "file": "${FILE_ESC}",
  "line": ${LINE},
  "col": ${COL},
  "varname": "${VARNAME_ESC}",
  "note": {
    "line": ${NOTE_LINE},
    "col": ${NOTE_COL:-0},
    "message": "${NOTE_MSG_ESC}"
  }
}
EOF
    else
        cat >> "$FINDINGS" << EOF
{
  "detector": "${DETECTOR}",
  "severity": "${SEVERITY}",
  "rule": "${RULE}",
  "file": "${FILE_ESC}",
  "line": ${LINE},
  "col": ${COL},
  "varname": "${VARNAME_ESC}"
}
EOF
    fi
}