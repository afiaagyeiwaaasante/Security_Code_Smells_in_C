#!/usr/bin/env bash
# detect_define_credential.sh <xml> <src> <findings>
#
# Detector: define_credential
# Detects #define macros where:
#   - the macro name matches a credential keyword (PASSWORD, SECRET, TOKEN, etc.)
#   - the value is a quoted string literal.
# Rule: SCS010-PASSWD-DEFINE
#
# Strategy (XPath only, no srcQL, no Python):
#
#   //*[local-name()='define']
#     [*[local-name()='macro']/*[local-name()='name'][<credential-check>]]
#     [starts-with(normalize-space(*[local-name()='value']),'"')]
#
#   Credential keyword check uses XPath translate() for case-insensitive
#   matching — no Python regex required.
#
# Requires: xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

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

echo "    strategy : XPath -- #define with credential macro name and quoted string value"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

UP='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LO='abcdefghijklmnopqrstuvwxyz'

CRED_MACRO="contains(translate(.,'${UP}','${LO}'),'password') or contains(translate(.,'${UP}','${LO}'),'passwd') or contains(translate(.,'${UP}','${LO}'),'secret') or contains(translate(.,'${UP}','${LO}'),'token') or contains(translate(.,'${UP}','${LO}'),'credential') or contains(translate(.,'${UP}','${LO}'),'passphrase') or contains(translate(.,'${UP}','${LO}'),'pwd')"

DEFINE_XPATH="//*[local-name()='define'][*[local-name()='macro']/*[local-name()='name'][${CRED_MACRO}]][starts-with(normalize-space(*[local-name()='value']),'\"')]"

POS=$(xmllint --xpath "string(${DEFINE_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -z "$POS" ]; then
    echo "[ define_credential ] No smell detected."
    exit 0
fi

LINE=${POS%%:*}
COL=${POS##*:}

MACRO_NAME=$(xmllint --xpath \
    "string(${DEFINE_XPATH}/*[local-name()='macro']/*[local-name()='name'])" \
    "$XML" 2>/dev/null)

echo "    macro    : $MACRO_NAME"
echo "    position : $LINE:$COL"
echo

write_finding \
    --findings  "$FINDINGS" \
    --detector  "define_credential" \
    --severity  "error" \
    --classification  "vulnerability" \
    --rule      "SCS010-PASSWD-DEFINE" \
    --file      "$FILENAME" \
    --line      "$LINE" \
    --col       "$COL" \
    --varname   "${MACRO_NAME:-?}" \
    --note-line "$LINE" \
    --note-col  "$COL" \
    --note-msg  "#define '${MACRO_NAME}' set to a string literal -- hardcoded credential in preprocessor macro"

echo "    finding: ${FILENAME}:${LINE}:${COL} -- #define '${MACRO_NAME}' = string literal"
echo
echo "[ define_credential ] 1 finding(s) written to $FINDINGS"
