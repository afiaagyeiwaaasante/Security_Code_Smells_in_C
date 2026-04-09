# SCS007 — Signed/Unsigned Confusion Detection Pipeline

## Overview

The SCS007 pipeline detects CWE-195 (Use of Signed Type Where Unsigned Expected)
by statically analysing C/C++ source files for calls to memory and string
functions — `malloc`, `memcpy`, `memmove`, `strncpy` — where the size argument
is a signed integer with no positivity guard (`data > 0`) in the surrounding
function body.

The pipeline follows the same three-stage srcML → srcslice → srcattributor
architecture used across SCS003–SCS010.

## Stages

### Stage 1 — srcML (Annotation)

```
srcml <source.c> --position --hash -o <output.xml>
```

Converts the C/C++ source file into srcML XML with positional attributes
(`pos:start`, `pos:end`) and a content hash.

**Key XML elements used by this pipeline:**

| Source construct | srcML element |
|---|---|
| `malloc(data)` | `<call pos:start="L:C"><name>malloc</name>...` |
| `memcpy(dst, src, data)` | `<call pos:start="L:C"><name>memcpy</name>...` |
| `memmove(dst, src, data)` | `<call pos:start="L:C"><name>memmove</name>...` |
| `strncpy(dst, src, data)` | `<call pos:start="L:C"><name>strncpy</name>...` |
| `if (data > 0)` | `<condition>...<operator>&gt;</operator>...</condition>` |
| function body | `<function>...</function>` |
| C++ destructor | `<destructor>...</destructor>` |
| C++ constructor | `<constructor>...</constructor>` |

### Stage 2 — srcslice (Slice JSON)

```
srcslice -i <output.xml> -o <output.json>
```

Produces a data-slice JSON mapping each variable declaration and use site
to a unique hash, enabling multi-file interprocedural detection when source
files are combined into a single srcML archive.

### Stage 3 — srcattributor (Attribution)

```
srcattributor -i <output.json> -o <output.xml>
```

Merges the slice information back into the srcML XML. The annotated XML is
the final input consumed by the detectors.

## Detectors

### Detector 1 — `detect_signed_malloc.sh`

**Target:** `malloc()` calls with no positivity guard.
**Rule:** `SCS007-SIGNED-MALLOC` / `signedUnsignedConversion`

**Strategy:**
1. Split the annotated XML into per-block sections on `<function>`, `<destructor>`, `<constructor>` boundaries.
2. Skip blocks with no `malloc` substring.
3. Find all `<call>...<name>malloc</name>...` elements with `pos:start` attributes.
4. Extract all `<condition>` sub-elements from the same block.
5. Check whether any condition contains `&gt;` (the XML-escaped `>` operator).
6. If no `&gt;` guard is found → emit `warning [signedUnsignedConversion]`.

**Bad pattern (flagged):**
```c
/* condition only has < (upper bound), no > (lower bound) */
if (data < 100) {
    char *buf = (char *)malloc(data);   /* FLAW: data may be negative */
}
```

**Good pattern (suppressed):**
```c
if (data > 0) {
    char *buf = (char *)malloc(data);   /* FIX: positivity guard present */
}
```

---

### Detector 2 — `detect_signed_memcpy.sh`

**Target:** `memcpy()` and `memmove()` calls with no positivity guard.
**Rule:** `signedUnsignedConversion`

Same block-splitting and guard-check strategy as Detector 1. Both `memcpy`
and `memmove` are covered by a single regex (`memcpy|memmove`) because their
detection pattern is identical — both accept a signed value as a `size_t`
count argument. The finding message identifies which sink was matched.

---

### Detector 3 — `detect_signed_strncpy.sh`

**Target:** `strncpy()` calls with no positivity guard.
**Rule:** `signedUnsignedConversion`

Same strategy. Targets `<call><name>strncpy</name>...` with the same
`&gt;` condition check.

## Guard Logic

All three detectors share the same positivity guard check:

```python
POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)

conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)

if any(POSITIVE_GUARD.search(c) for c in conditions):
    continue  # positivity guard present — skip
```

`&gt;` in a srcML `<condition>` element covers:
- `data > 0` — strict lower bound
- `data >= 1` — non-strict lower bound (`&gt;=` contains `&gt;`)
- `data > 0 && data <= MAX` — combined lower + upper bound

The check is scoped to `<condition>` blocks only — `&gt;` in a `<decl>`
initialiser or other element does not suppress the finding.

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs all three stages then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings
