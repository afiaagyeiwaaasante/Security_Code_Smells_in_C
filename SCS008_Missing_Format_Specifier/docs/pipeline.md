# SCS008 — Missing Format Specifier Detection Pipeline

## Overview

The SCS008 pipeline detects CWE-134 (Use of Externally-Controlled Format
String) by statically analysing C/C++ source files for calls to printf-family
functions where the format argument is a variable rather than a string literal.

The pipeline follows the same three-stage srcML → srcslice → srcattributor
architecture used in SCS003 through SCS007.

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
| function body | `<function>…</function>` |
| destructor body | `<destructor>…</destructor>` |
| constructor body | `<constructor>…</constructor>` |

The critical distinction: a variable reference produces `<name>`, while a
string literal produces `<literal type="string">`. The detector checks which
one appears as the format argument.

### Stage 2 — srcslice (Slice JSON)

```
srcslice -i <output.xml> -o <output.json>
```

Produces a data-slice JSON that maps each variable declaration and use to a
unique hash via `slice:decl` and `slice:use` attributes. Used for
interprocedural data-flow context.

### Stage 3 — srcattributor (Attribution)

```
srcattributor -i <output.json> -o <output.xml>
```

Merges the slice information back into the srcML XML. The annotated XML is the
final input consumed by all three detectors.

## Detectors

### Detector 1 — `detect_printf_direct.sh`

**Targets:** `printf`, `vprintf`
**Format argument:** index 0 (first argument)

**Strategy:**
1. Split the XML into per-block sections on `<function>`, `<destructor>`, and `<constructor>` boundaries.
2. For each block, find all `<call>` elements whose `<name>` is `printf` or `vprintf`.
3. Extract the `<argument_list>` and parse the first `<argument>`.
4. If the first argument contains a `<literal>` element → guarded (skip).
5. If the first argument contains only a `<name>` (variable) → emit `warning [SCS008-PRINTF]`.

**Handles:** C functions, C++ destructor/constructor bodies (flows 83/84).

### Detector 2 — `detect_fprintf_direct.sh`

**Targets:** `fprintf`, `vfprintf`
**Format argument:** index 1 (second argument, after the `FILE *` stream)

Same strategy as Detector 1, but checks `args[1]` (the second argument) rather
than `args[0]`, because the first argument to `fprintf` is the output stream.

### Detector 3 — `detect_syslog_direct.sh`

**Targets:** `syslog`
**Format argument:** index 1 (second argument, after the priority level)

Same strategy as Detector 2. `syslog(priority, format, ...)` — the format is
the second argument, so `args[1]` is checked for a literal.

## Guard Logic

All three detectors share the same literal-check:

```python
LITERAL_PAT = re.compile(r'<literal\b')
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)

arglist_m = re.search(r'<argument_list\b[^>]*>(.*?)</argument_list>', call_text, re.DOTALL)
args = ARG_SPLIT.findall(arglist_m.group(1))

if LITERAL_PAT.search(args[FORMAT_ARG_INDEX]):
    continue  # guarded — literal format string present
```

Where `FORMAT_ARG_INDEX` is `0` for `printf`/`vprintf` and `1` for
`fprintf`/`vfprintf`/`syslog`.

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs all three stages then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings

## XML Pattern: Bad vs Good

**Bad** — `printf(data)`: variable as format arg, no `<literal>` in first argument:
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
