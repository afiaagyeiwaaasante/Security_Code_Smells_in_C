# SCS001 Detection Pipeline

## Overview

The pipeline converts a C source file into a structured XML representation,
then runs a structural query to locate calls to dangerous functions.

```
source.c  ──►  srcml  ──►  annotated XML  ──►  srcQL query  ──►  XPath extraction  ──►  findings.json
```

---

## Stage 1 — srcml (parse)

```bash
srcml source.c --position --hash -o source.xml
```

- Parses the C source into a srcML XML archive
- `--position` annotates every node with `pos:start` and `pos:end` attributes
- `--hash` adds a content hash to each unit for change detection
- No data flow or slice analysis is needed — CWE-242 detection is purely structural

**Multi-file variant:** `smell_report_multi.sh` passes all source files to a single
`srcml` invocation, producing one multi-unit archive. srcQL then queries across all
units in one pass, enabling cross-file detection.

```bash
srcml file_a.c file_b.c --position --hash -o combined.xml
```

---

## Stage 2 — srcQL query

```
FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
```

Matches any function body in the translation unit that contains a call to `gets()`.

- `$T $FUNC($PARAMS) {}` — matches any function definition
- `CONTAINS gets($DEST)` — requires a call to `gets` with any single argument

The query returns a srcML XML fragment containing the matched function(s).

---

## Stage 3 — XPath position extraction

Three XPath expressions are applied to the srcQL result:

| Extract | XPath target | Used for |
|---------|-------------|----------|
| Filename | `//unit/@filename` | finding file path |
| Call site | `//call/name[.="gets"]/../@pos:start` | finding line:col |
| Buffer argument | `//call/name[.="gets"]/../argument_list/argument//name` | variable name in note |
| Surrounding function | `//function/@pos:start` | note line:col |

---

## Stage 4 — Finding emission

Each match produces one finding in `findings.json`:

```json
{
  "detector": "dangerous_function",
  "severity": "warning",
  "rule": "dangerousFunction",
  "file": "path/to/source.c",
  "line": 8,
  "col": 14,
  "varname": "dest",
  "note": {
    "line": 3,
    "col": 1,
    "message": "gets() is inherently dangerous — use fgets(dest, size, stdin) instead"
  }
}
```

---

## Entry points

| Script | Purpose |
|--------|---------|
| `src/smell_report.sh <file.c>` | Single-file analysis |
| `src/smell_report_multi.sh <a.c> <b.c> ...` | Multi-file combined analysis |
| `testsuites/CWE242/run_test.sh` | Run all test cases |
