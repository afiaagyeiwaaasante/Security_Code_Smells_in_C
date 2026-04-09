# SCS002 Detection Pipeline

## Overview

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
- No data flow or slice analysis needed — detection is purely structural

---

## Stage 2 — srcQL query

```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
```

Matches any function body containing a `malloc` call whose argument is a
multiplication expression. This covers the pattern `malloc(n * sizeof(T))`
where integer overflow in `n * sizeof(T)` can produce a smaller allocation
than intended.

---

## Stage 3 — XPath position extraction

| Extract | XPath target | Used for |
|---------|-------------|----------|
| Filename | `//unit/@filename` | finding file path |
| Call site | `//call/name[.="malloc"]/../@pos:start` | finding line:col |
| Count variable | `//call/name[.="malloc"]/../argument_list/argument//name` | varname in note |
| Surrounding function | `//function/@pos:start` | note line:col |

---

## Stage 4 — Finding emission

```json
{
  "detector": "buffer_size_mismatch",
  "severity": "warning",
  "rule": "bufferSizeMismatch",
  "file": "path/to/source.c",
  "line": 7,
  "col": 10,
  "varname": "n",
  "note": {
    "line": 3,
    "col": 1,
    "message": "malloc(n * sizeof(...)) may overflow — use calloc(n, sizeof(...)) instead"
  }
}
```

---

## Entry points

| Script | Purpose |
|--------|---------|
| `src/smell_report.sh <file.c>` | Single-file analysis |
| `testsuites/CWE680/run_test.sh` | Run all test cases |
