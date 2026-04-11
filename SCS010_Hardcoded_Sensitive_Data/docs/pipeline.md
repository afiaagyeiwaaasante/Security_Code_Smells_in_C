# SCS010 — Hardcoded Sensitive Data Detection Pipeline

## Overview

The SCS010 pipeline detects CWE-259 (Use of Hard-coded Password) by statically
analysing C/C++ source files for credential values embedded as string literals
directly in source code — in variable initialisers, preprocessor macros, or
authentication comparisons.

The pipeline uses srcML annotation followed by XPath queries — no Python, no srcQL.

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

**Strategy — Part A (declaration, XPath):**

```xpath
//*[local-name()='decl']
  [<credential-name-check>]
  [*[local-name()='init']
    [.//*[local-name()='literal'][@type='string'][string-length(.)>2]]
    [not(.//*[local-name()='call'])]]
```

- The credential name check uses `contains(translate(*[local-name()='name'],'A-Z','a-z'),'keyword')` on the `<name>` child — case-insensitive, no Python regex needed.
- `[string-length(.)>2]` excludes empty/single-char literals (`""`, `"x"`).
- `[not(.//*[local-name()='call'])]` guards against `getenv()`-style initialisation.

**Strategy — Part B (strcpy, XPath):**

```xpath
//*[local-name()='call']
  [*[local-name()='name'][.='strcpy']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [.//*[local-name()='name'][<credential-name-check>]]]
  [*[local-name()='argument_list']/*[local-name()='argument'][2]
    [.//*[local-name()='literal'][@type='string']]]
```

**Credential keywords:** `password`, `passwd`, `pwd`, `secret`, `token`, `credential`, `passphrase` (matched case-insensitively via XPath `translate()`, substring match to cover `password_`, `m_password`, `MY_PASSWORD`, etc.)

### Detector 2 — `detect_define_credential.sh`

**Targets:** Preprocessor `#define` macros with credential names.
**Rule:** SCS010-PASSWD-DEFINE

**Strategy (XPath):**

```xpath
//*[local-name()='define']
  [*[local-name()='macro']/*[local-name()='name'][<credential-name-check>]]
  [starts-with(normalize-space(*[local-name()='value']),'"')]
```

- Macro `<name>` is checked against credential keywords via `translate()`.
- `starts-with(normalize-space(...),'"')` detects a quoted string value.

### Detector 3 — `detect_strcmp_hardcoded.sh`

**Targets:** `strcmp()` and `strncmp()` calls with a string literal argument.
**Rule:** SCS010-PASSWD-STRCMP

**Strategy (XPath):**

```xpath
//*[local-name()='call']
  [*[local-name()='name'][.='strcmp' or .='strncmp']]
  [*[local-name()='argument_list']
    /*[local-name()='argument']
    [.//*[local-name()='literal'][@type='string']]]
```

A finding is emitted when any argument of `strcmp`/`strncmp` is a string literal — the literal is the hardcoded credential in the comparison.

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
