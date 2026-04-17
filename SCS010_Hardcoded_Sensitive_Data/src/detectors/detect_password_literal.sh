#!/usr/bin/env bash
# detect_password_literal.sh <xml> <src> <findings>
#
# Detector: password_literal
# Detects:
#   1. Variable declarations where the name matches a credential keyword AND
#      the init value is a string literal (no function call in init).
#   2. strcpy(credential_var, "literal") — hardcoded password copied into buffer.
# Rule: SCS010-PASSWD-VAR
#
# Strategy (XPath only, no srcQL, no Python):
#
#   Pattern 1 — <decl> with credential name + literal init:
#     //*[local-name()='decl']
#       [<credential-name-check>]
#       [*[local-name()='init']
#         [.//*[local-name()='literal'][@type='string'][string-length(.)>2]]
#         [not(.//*[local-name()='call'])]]
#
#   Pattern 2 — strcpy(cred_var, "literal"):
#     //*[local-name()='call']
#       [*[local-name()='name'][.='strcpy']]
#       [*[local-name()='argument_list']/*[local-name()='argument'][1]
#         [.//*[local-name()='name'][<cred-check>]]]
#       [*[local-name()='argument_list']/*[local-name()='argument'][2]
#         [.//*[local-name()='literal'][@type='string']]]
#
#   Credential keyword check uses XPath translate() for case-insensitive
#   matching — no Python regex required.
#
# Requires: xmllint

source "$(dirname "$0")/../../../shared/lib/write_finding.sh"

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

echo "    strategy : XPath -- credential-named decl with literal init; strcpy into cred var"
echo

FILENAME=$(xmllint --xpath \
    'string(//*[local-name()="unit"]/@filename)' "$XML" 2>/dev/null)

UP='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LO='abcdefghijklmnopqrstuvwxyz'

# Credential keyword predicate on <decl> direct <name> child (case-insensitive)
CRED="contains(translate(*[local-name()='name'],'${UP}','${LO}'),'password') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'passwd') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'secret') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'token') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'credential') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'passphrase') or contains(translate(*[local-name()='name'],'${UP}','${LO}'),'pwd')"

# Pattern 1: credential-named variable initialised to a string literal
DECL_XPATH="//*[local-name()='decl'][${CRED}][*[local-name()='init'][.//*[local-name()='literal'][@type='string'][string-length(.)>2]][not(.//*[local-name()='call'])]]"

POS=$(xmllint --xpath "string(${DECL_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -n "$POS" ]; then
    LINE=${POS%%:*}
    COL=${POS##*:}

    VAR_NAME=$(xmllint --xpath \
        "string(${DECL_XPATH}/*[local-name()='name'])" \
        "$XML" 2>/dev/null)
    FUNC_NAME=$(xmllint --xpath \
        "string(${DECL_XPATH}/ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][1]/*[local-name()='name'])" \
        "$XML" 2>/dev/null)

    echo "    pattern  : decl literal init"
    echo "    variable : $VAR_NAME"
    echo "    function : $FUNC_NAME"
    echo "    position : $LINE:$COL"
    echo

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "password_literal" \
        --severity  "error" \
        --classification  "vulnerability" \
        --rule      "SCS010-PASSWD-VAR" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${VAR_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "Variable '${VAR_NAME}' initialised to a string literal -- hardcoded sensitive data"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- '${VAR_NAME}' initialised to string literal"
    echo
    echo "[ password_literal ] 1 finding(s) written to $FINDINGS"
    exit 0
fi

# Pattern 2: strcpy(credential_var, "literal")
# Credential keyword predicate on arbitrary descendant <name> (arg variable name)
CRED_NAME_CHECK="contains(translate(.,'${UP}','${LO}'),'password') or contains(translate(.,'${UP}','${LO}'),'passwd') or contains(translate(.,'${UP}','${LO}'),'secret') or contains(translate(.,'${UP}','${LO}'),'token') or contains(translate(.,'${UP}','${LO}'),'credential') or contains(translate(.,'${UP}','${LO}'),'passphrase') or contains(translate(.,'${UP}','${LO}'),'pwd')"

STRCPY_XPATH="//*[local-name()='call'][*[local-name()='name'][.='strcpy']][*[local-name()='argument_list']/*[local-name()='argument'][1][.//*[local-name()='name'][${CRED_NAME_CHECK}]]][*[local-name()='argument_list']/*[local-name()='argument'][2][.//*[local-name()='literal'][@type='string']]]"

POS=$(xmllint --xpath "string(${STRCPY_XPATH}/@*[local-name()='start'])" "$XML" 2>/dev/null)

if [ -n "$POS" ]; then
    LINE=${POS%%:*}
    COL=${POS##*:}

    FUNC_NAME=$(xmllint --xpath \
        "string(${STRCPY_XPATH}/ancestor::*[local-name()='function' or local-name()='destructor' or local-name()='constructor'][1]/*[local-name()='name'])" \
        "$XML" 2>/dev/null)

    echo "    pattern  : strcpy into credential buffer"
    echo "    function : $FUNC_NAME"
    echo "    position : $LINE:$COL"
    echo

    write_finding \
        --findings  "$FINDINGS" \
        --detector  "password_literal" \
        --severity  "error" \
        --classification  "vulnerability" \
        --rule      "SCS010-PASSWD-VAR" \
        --file      "$FILENAME" \
        --line      "$LINE" \
        --col       "$COL" \
        --varname   "${FUNC_NAME:-?}" \
        --note-line "$LINE" \
        --note-col  "$COL" \
        --note-msg  "strcpy into credential buffer from a string literal -- hardcoded sensitive data in ${FUNC_NAME}()"

    echo "    finding: ${FILENAME}:${LINE}:${COL} -- strcpy into credential buffer in ${FUNC_NAME}()"
    echo
    echo "[ password_literal ] 1 finding(s) written to $FINDINGS"
    exit 0
fi

echo "[ password_literal ] No smell detected."
