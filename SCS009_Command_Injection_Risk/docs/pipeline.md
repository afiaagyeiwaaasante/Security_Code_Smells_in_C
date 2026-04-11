# SCS009 — Command Injection Risk Detection Pipeline

## Overview

The SCS009 pipeline detects CWE-78 (Improper Neutralisation of Special Elements
used in an OS Command — OS Command Injection) by statically analysing C/C++
source files for calls to OS command sinks (`system`, `popen`, `execl`, `execlp`)
where the command argument is a variable rather than a string literal, AND a
user-input source (`fgets` or `getenv`) is present in the same function block.

The pipeline uses srcML annotation, srcQL for function scoping, and XPath for guard checks — no Python.

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
| `system(data)` | `<call><name>system</name><argument_list>(<argument><expr><name>data</name></expr></argument>)</argument_list></call>` |
| `system("ls -l")` | `<call><name>system</name><argument_list>(<argument><expr><literal type="string">"ls -l"</literal></expr></argument>)</argument_list></call>` |
| `fgets(data, n, stdin)` | `<call><name>fgets</name>…</call>` |
| `getenv("ADD")` | `<call><name>getenv</name>…</call>` |
| function body | `<function>…</function>` |
| destructor body | `<destructor>…</destructor>` |
| constructor body | `<constructor>…</constructor>` |

The critical distinction: a variable reference produces `<name>`, while a
string literal produces `<literal type="string">`. The detector checks which
one appears as the command argument.

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

### Detector 1 — `detect_system_tainted.sh`

**Targets:** `system()`
**Command argument:** index 1 (first argument)
**Rule:** SCS009-SYSTEM

**Strategy (srcQL + XPath):**

Stage 1 — srcQL scopes to the function body:
```
FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)
```

XPath on result: non-literal first arg check + `count(fgets/getenv) > 0`.
Stage 2 — XPath `ancestor::` fallback for destructors/constructors.

### Detector 2 — `detect_popen_tainted.sh`

**Targets:** `popen()`
**Command argument:** index 1 (first argument — the command string; second argument is the mode)
**Rule:** SCS009-POPEN

Same srcQL + XPath structure as Detector 1 with `popen` as the sink name.

### Detector 3 — `detect_execl_tainted.sh`

**Targets:** `execl()`, `execlp()`
**Path argument:** index 1 (first argument — the executable path)
**Rule:** SCS009-EXECL

**Strategy (srcQL + XPath):**

Unlike Detectors 1 and 2, this detector uses srcQL to scope to the function body first, then applies XPath guards on the scoped result:

```
FIND $T $FUNC($PARAMS) {} CONTAINS execl($PATH)
FIND $T $FUNC($PARAMS) {} CONTAINS execlp($PATH)
```

XPath on the srcQL result checks:
1. The first `<argument>` has no `<literal>` (non-hardcoded path).
2. A flat `count()` confirms fgets/getenv is present — no `ancestor::` needed since srcQL already scoped the XML to the function body.

A destructor/constructor fallback stage uses the full XPath `ancestor::` predicate directly on the original XML.

## Guard Logic

Detectors 1 and 2 use a single XPath predicate chain. Detector 3 splits the guard across srcQL (function scope) and two sequential XPath checks (literal check, then taint count). The effective guard is the same:

```xpath
[*[local-name()='argument_list']
  /*[local-name()='argument'][1]
  [not(.//*[local-name()='literal'])]]
[ancestor::*[local-name()='function' or
             local-name()='destructor' or
             local-name()='constructor']
  [.//*[local-name()='call']
    [*[local-name()='name'][.='fgets' or .='getenv']]]]
```

A finding is emitted only when BOTH conditions hold:
- The sink call's first argument has no `<literal>` child (variable, not hardcoded command), AND
- The enclosing function/destructor/constructor block also contains a `fgets` or `getenv` call (taint source present).

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs all three stages then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings

## XML Pattern: Bad vs Good

**Bad** — `system(data)`: variable as command arg, taint source present:
```xml
<call pos:start="24:5" pos:end="24:16">
  <name>system</name>
  <argument_list>(
    <argument><expr><name>data</name></expr></argument>
  )</argument_list>
</call>
```

**Good** — `system("ls -l")`: `<literal>` as command arg:
```xml
<call pos:start="21:5" pos:end="21:19">
  <name>system</name>
  <argument_list>(
    <argument><expr><literal type="string">"ls -l"</literal></expr></argument>
  )</argument_list>
</call>
```
