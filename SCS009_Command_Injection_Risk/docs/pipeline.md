# SCS009 — Command Injection Risk Detection Pipeline

## Overview

The SCS009 pipeline detects CWE-78 (Improper Neutralisation of Special Elements
used in an OS Command — OS Command Injection) by statically analysing C/C++
source files for calls to OS command sinks (`system`, `popen`, `execl`, `execlp`)
where the command argument is a variable rather than a string literal, AND a
user-input source (`fgets` or `getenv`) is present in the same function block.

The pipeline follows the same three-stage srcML → srcslice → srcattributor
architecture used in SCS003 through SCS008.

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
**Command argument:** index 0 (first and only argument)
**Rule:** SCS009-SYSTEM

**Strategy:**
1. Split the XML into per-block sections on `<function>`, `<destructor>`, and `<constructor>` boundaries.
2. Guard check: skip blocks with no `<name>fgets</name>` or `<name>getenv</name>` — no taint source means goodG2B pattern.
3. For each `system()` call in the block, extract the first `<argument>`.
4. If the first argument contains a `<literal>` element → safe (literal command, skip).
5. If the first argument contains only a `<name>` (variable) → emit `warning [SCS009-SYSTEM]`.

### Detector 2 — `detect_popen_tainted.sh`

**Targets:** `popen()`
**Command argument:** index 0 (first argument — the command string; second argument is the mode)
**Rule:** SCS009-POPEN

Same strategy as Detector 1. Checks `args[0]` — if it is a `<literal>`, the
call is safe; if it is a `<name>` variable AND a taint source exists in the
block, emit a finding.

### Detector 3 — `detect_execl_tainted.sh`

**Targets:** `execl()`, `execlp()`
**Path argument:** index 0 (first argument — the executable path)
**Rule:** SCS009-EXECL

Same strategy. `execl(path, arg0, ...)` — if `path` is a variable and a taint
source exists in the block, emit a finding.

## Guard Logic

All three detectors share the same two-part guard:

```python
# Guard 1: taint source must be present in the block
INPUT_SOURCE = re.compile(r'<name[^>]*>\s*(?:fgets|getenv)\s*</name>')
if not INPUT_SOURCE.search(block):
    continue  # goodG2B — no user input, safe call

# Guard 2: command argument must not be a string literal
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
LITERAL_PAT = re.compile(r'<literal\b')

args = ARG_SPLIT.findall(args_content)
if LITERAL_PAT.search(args[0]):
    continue  # literal command — safe call (goodG2B hardcoded command)
```

A finding is emitted only when BOTH conditions hold:
- A taint source (`fgets`/`getenv`) is present in the same block, AND
- The sink call's command argument is a variable, not a literal.

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
