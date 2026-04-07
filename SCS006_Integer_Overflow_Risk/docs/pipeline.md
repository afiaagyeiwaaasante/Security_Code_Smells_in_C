# SCS006 — Integer Overflow Risk Detection Pipeline

## Overview

The SCS006 pipeline detects CWE-190 (Integer Overflow or Wraparound) by
statically analysing C/C++ source files for arithmetic operations — multiply,
add, and increment — that lack an upper-bound guard against integer overflow.

The pipeline follows the same three-stage srcML → srcslice → srcattributor
architecture used in SCS003, SCS004, and SCS005.

## Stages

### Stage 1 — srcML (Annotation)

```
srcml <source.c> --position --hash -o <output.xml>
```

Converts the C/C++ source file into srcML XML with positional attributes
(`pos:start`, `pos:end`) and a content hash. Every syntactic element —
operators, function names, conditions — becomes a tagged XML element that
the detectors can query.

**Key XML elements used by this pipeline:**

| Source construct        | srcML element                              |
|-------------------------|--------------------------------------------|
| `data * 2`              | `<operator pos:start="L:C">*</operator>`   |
| `data + 1`              | `<operator pos:start="L:C">+</operator>`   |
| `data++` / `++data`     | `<operator pos:start="L:C">++</operator>`  |
| `if (data < INT_MAX)`   | `<condition>…<name>INT_MAX</name>…</condition>` |
| function body           | `<function>…</function>`                   |
| destructor body         | `<destructor>…</destructor>`               |

### Stage 2 — srcslice (Slice JSON)

```
srcslice -i <output.xml> -o <output.json>
```

Produces a data-slice JSON that maps each variable declaration and use to a
unique hash. This enables interprocedural detection when source files are
combined into a multi-unit srcML archive.

### Stage 3 — srcattributor (Attribution)

```
srcattributor -i <output.json> -o <output.xml>
```

Merges the slice information back into the srcML XML, annotating `<decl>`
and `<name>` elements with `slice:decl` and `slice:use` attributes. The
annotated XML is the final input consumed by the detectors.

## Detectors

Three detectors run on the annotated XML.

### Detector 1 — `detect_unchecked_multiply.sh`

**Pattern:** `<operator>*</operator>` inside any function/destructor/constructor block.

**Strategy:**
1. Split the XML into per-block sections on `<function>`, `<destructor>`, and `<constructor>` elements.
2. For each block, find all `<operator>*</operator>` elements with positional attributes.
3. Extract all `<condition>` sub-elements from the block.
4. Check whether any condition contains a MAX constant (`INT_MAX`, `CHAR_MAX`, `SHRT_MAX`, `UINT_MAX`, `INT64_MAX`, `LLONG_MAX`).
5. If no MAX guard is found in any condition → emit `warning [integerOverflow]`.

**Handles:** C functions, C++ virtual methods (dispatched via reference or pointer), C++ destructor bodies.

### Detector 2 — `detect_unchecked_add.sh`

Same structure as Detector 1, but targets `<operator>+</operator>`.

**Edge case:** `bad_unsigned_int_add_01.c` initialises `data = UINT_MAX` — the `UINT_MAX` token appears in a `<decl>` initialiser, not in a `<condition>`. The detector correctly ignores MAX tokens outside `<condition>` elements.

### Detector 3 — `detect_unchecked_increment.sh`

**Pattern:** `<operator>++</operator>` (covers both prefix `++data` and postfix `data++`).

**Strategy:** Same condition-based guard check as Detectors 1 and 2. The detector reads the full annotated XML directly (no srcQL) and splits on function/destructor/constructor boundaries.

## Post-filter: Condition Guard Logic

All three detectors share the same guard-check approach:

```python
conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)
if any(MAX_PATTERN.search(c) for c in conditions):
    continue  # guarded — skip
```

Where `MAX_PATTERN` matches:

```
INT_MAX | CHAR_MAX | SHRT_MAX | UINT_MAX | INT64_MAX | LLONG_MAX
```

This approach is conservative: it only suppresses a finding when a MAX constant
appears in an explicit `<condition>` block, not in any other position (e.g.,
initialisers or comments).

## Entry Point

```
bash src/smell_report.sh <source.c|cpp> [output_dir]
```

Runs all three stages then all three detectors, writing:
- `<name>_report_<timestamp>.txt` — human-readable report
- `<name>_findings_<timestamp>.json` — machine-readable findings (one JSON object per finding)

## Interprocedural Detection

For cross-function flows (data created in one function, arithmetic in another),
use `smell_report_multi.sh` which combines multiple source files into a single
srcML archive before running detection.
