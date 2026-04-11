# SCS008 — Missing Format Specifier Detection Pipeline

## Overview

The SCS008 pipeline detects CWE-134 (Use of Externally-Controlled Format
String) by statically analysing C/C++ source files for calls to printf-family
functions where the format argument is a variable rather than a string literal,
AND a user-input source (`fgets`, `getenv`, `scanf`, `fscanf`) is present in
the same function block.

The pipeline uses srcML annotation, srcQL for function scoping, and XPath for
guard checks — no Python.

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
| `printf(data)` | `<call><name>printf</name><argument_list>(<argument><expr><name>data</name></expr></argument>)</argument_list></call>` |
| `printf("%s\n", data)` | `<call><name>printf</name><argument_list>(<argument><expr><literal type="string">"%s\n"</literal></expr></argument>…)</argument_list></call>` |
| `fgets(data, n, stdin)` | `<call><name>fgets</name>…</call>` |
| function body | `<function>…</function>` |
| destructor body | `<destructor>…</destructor>` |
| constructor body | `<constructor>…</constructor>` |

The critical distinction: a variable reference produces `<name>`, while a
string literal produces `<literal type="string">`. The detector checks which
one appears as the format argument.

## Detectors

All three detectors share the same two-stage structure.

### Detector 1 — `detect_printf_direct.sh`

**Targets:** `printf`, `vprintf`
**Format argument:** index 1 (first argument)
**Rule:** SCS008-PRINTF

**Stage 1 — srcQL (function scope):**
```
FIND $T $FUNC($PARAMS) {} CONTAINS printf($FMT)
```

**Stage 1 guard — XPath on srcQL result:**
1. The first `<argument>` does NOT contain a `<literal>` (non-hardcoded format string), AND
2. A flat `count()` confirms a taint source (`fgets`, `getenv`, `scanf`, `fscanf`) is present — no `ancestor::` needed since srcQL already scoped the XML to the function body.

**Stage 2 — XPath fallback for `<destructor>`/`<constructor>`:**

srcQL requires a return type and does not match C++ destructor/constructor blocks.
An `ancestor::` predicate on the original XML covers these cases, applying the
same taint source co-occurrence check.

### Detector 2 — `detect_fprintf_direct.sh`

**Targets:** `fprintf`, `vfprintf`
**Format argument:** index 2 (second argument — after the `FILE *` stream)
**Rule:** SCS008-FPRINTF

Same srcQL + XPath structure as Detector 1. The XPath literal check uses
`/*[local-name()='argument'][2]` instead of `[1]`.

### Detector 3 — `detect_syslog_direct.sh`

**Targets:** `syslog`
**Format argument:** index 2 (second argument — after the priority level)
**Rule:** SCS008-SYSLOG

Same structure as Detector 2. `syslog(priority, format, ...)` — format is the
second argument.

## Guard Logic

All three detectors apply a two-part guard on the srcQL-scoped result:

```xpath
-- Part 1: format arg non-literal (printf: arg 1; fprintf/syslog: arg 2) --
//*[local-name()='call'][*[local-name()='name'][.='printf' or .='vprintf']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]

-- Part 2: taint source present in same function --
count(//*[local-name()='call'][*[local-name()='name']
  [.='fgets' or .='getenv' or .='scanf' or .='fscanf']])
```

A finding is emitted only when Part 1 returns a non-empty position AND Part 2
returns a count > 0.

The Stage 2 XPath fallback expresses the same constraint for destructors/constructors
using `ancestor::` (taint source must be present in the same destructor/constructor block):

```xpath
//*[local-name()='call'][*[local-name()='name'][.='printf' or .='vprintf']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
  [ancestor::*[local-name()='destructor' or local-name()='constructor']
    [.//*[local-name()='call'][*[local-name()='name']
      [.='fgets' or .='getenv' or .='scanf' or .='fscanf']]]]
```

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs srcML annotation then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings

## XML Pattern: Bad vs Good

**Bad** — `printf(data)`: variable as format arg, taint source present:
```xml
<call>
  <name>printf</name>
  <argument_list>(
    <argument><expr><name>data</name></expr></argument>
  )</argument_list>
</call>
```

**Good** — `printf("%s\n", data)`: `<literal>` as first argument:
```xml
<call>
  <name>printf</name>
  <argument_list>(
    <argument><expr><literal type="string">"%s\n"</literal></expr></argument>,
    <argument><expr><name>data</name></expr></argument>
  )</argument_list>
</call>
```
