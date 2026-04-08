# SCS010 — Hardcoded Sensitive Data Detection Pipeline

## Overview

The SCS010 pipeline detects CWE-259 (Use of Hard-coded Password) by statically
analysing C/C++ source files for credential values embedded as string literals
directly in source code — in variable initialisers, preprocessor macros, or
authentication comparisons.

The pipeline follows the same three-stage srcML → srcslice → srcattributor
architecture used in SCS003 through SCS009.

## Stages

### Stage 1 — srcML (Annotation)

```
srcml <source.c> --position --hash -o <output.xml>
```

Converts the C/C++ source file into srcML XML with positional attributes
(`pos:start`, `pos:end`) and a content hash. Every syntactic element becomes
a tagged XML element that the detectors can query.

**Key XML elements used by this pipeline:**

| Source construct | srcML element |
|---|---|
| `char *password = "secret"` | `<decl><name>password</name><init><literal type="string">"secret"</literal></init></decl>` |
| `#define PASSWORD "ABCD1234!"` | `<cpp:define><cpp:macro><name>PASSWORD</name></cpp:macro><cpp:value>"ABCD1234!"</cpp:value></cpp:define>` |
| `strcmp(input, "secret")` | `<call><name>strcmp</name><argument_list>...<literal type="string">"secret"</literal>...</argument_list></call>` |

### Stage 2 — srcslice (Slice JSON)

```
srcslice -i <output.xml> -o <output.json>
```

Produces a data-slice JSON for interprocedural context (unused by the current
detectors, which operate on structural patterns).

### Stage 3 — srcattributor (Attribution)

```
srcattributor -i <output.json> -o <output.xml>
```

Merges the slice information back into the srcML XML — final input for detectors.

## Detectors

### Detector 1 — `detect_password_literal.sh`

**Targets:** Variable declarations and `strcpy` calls involving credential-named identifiers.
**Rule:** SCS010-PASSWD-VAR

**Strategy — Part A (declaration):**
1. Find all `<decl>` elements with `pos:start` position information.
2. Check if the declaration has an `<init>` section.
3. Guard: skip if `<init>` contains a `<call>` element (function call, not a literal — e.g., `getenv()`).
4. Guard: skip if the literal is an empty string `""` (buffer initialiser, not a credential).
5. Check if `<init>` contains a `<literal type="string">`.
6. Check if any `<name>` in the declaration matches a credential keyword.
7. Emit warning if both conditions hold.

**Strategy — Part B (strcpy):**
1. Find all `strcpy()` `<call>` elements.
2. Extract the two `<argument>` elements.
3. Check if the first argument contains a credential-keyword name.
4. Check if the second argument contains a `<literal type="string">`.
5. Emit warning if both conditions hold.

**Credential keywords:** `password`, `passwd`, `pwd`, `secret`, `api_key`, `token`, `credential`, `passphrase`, `private_key` (matched case-insensitively, substring match to cover `password_`, `m_password`, `MY_PASSWORD`, etc.)

### Detector 2 — `detect_define_credential.sh`

**Targets:** Preprocessor `#define` macros with credential names.
**Rule:** SCS010-PASSWD-DEFINE

**Strategy:**
1. Find all `<cpp:define>` elements.
2. Extract the `<cpp:macro><name>` — the macro name.
3. Check if the macro name matches a credential keyword.
4. Extract the `<cpp:value>` — the macro expansion.
5. Check if the value is a quoted string (`"..."` — matched via `^"[^"]*"$`).
6. Emit warning if both conditions hold.

### Detector 3 — `detect_strcmp_hardcoded.sh`

**Targets:** `strcmp()` and `strncmp()` calls with a string literal argument.
**Rule:** SCS010-PASSWD-STRCMP

**Strategy:**
1. Find all `strcmp`/`strncmp` `<call>` elements.
2. Extract all `<argument>` elements.
3. Check if ANY argument contains a `<literal type="string">`.
4. Emit warning if a literal is found — it indicates a hardcoded password in an authentication comparison.

## Guard Logic Summary

| Detector | Guard (what is skipped) |
|---|---|
| `password_literal` (decl) | Init contains `<call>` (function call) OR literal is `""` (empty) |
| `password_literal` (strcpy) | First arg has no credential keyword OR second arg has no literal |
| `define_credential` | Macro name has no credential keyword OR value is not a quoted string |
| `strcmp_hardcoded` | No literal in any argument |

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs all three stages then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings

## XML Pattern: Bad vs Good

**Bad — variable with credential name initialised to literal:**
```xml
<decl pos:start="12:5" pos:end="12:35">
  <type><specifier>const</specifier><name>char</name><modifier>*</modifier></type>
  <name>password</name>
  <init>= <expr><literal type="string">"ABCD1234!"</literal></expr></init>
</decl>
```

**Good — variable initialised via function call (not a literal):**
```xml
<decl pos:start="19:5" pos:end="19:49">
  <type><specifier>const</specifier><name>char</name><modifier>*</modifier></type>
  <name>password</name>
  <init>= <expr>
    <call><name>getenv</name><argument_list>(<argument><expr>
      <literal type="string">"APP_PASSWORD"</literal>
    </expr></argument>)</argument_list></call>
  </expr></init>
</decl>
```
Note: the good case has a `<call>` in the `<init>` — the detector's guard skips it.
