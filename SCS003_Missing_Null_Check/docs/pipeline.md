# Detection pipeline

## Overview
```
source.c
   │
   ▼
srcml --position --hash        →  source.c.xml   (srcML annotated AST)
   │
   ▼
srcslice -i source.c.xml       →  source.json    (data-flow slice data)
   │
   ▼
srcattributor -i source.json   →  source.c.xml   (slice attrs merged into XML)
   │
   ▼
detect_cwe476.py               →  smell report   (cppcheck-style output)
```

## Stage 1 — srcml

Converts C source into srcML XML. Both `--position` and `--hash` are
required by downstream tools:

- `--position` adds `pos:start="line:col"` to every node
- `--hash` embeds a file hash that srcattributor uses to locate the
  correct srcML unit when merging slice data
```bash
srcml source.c -l C --position --hash -o source.c.xml
```

## Stage 2 — srcslice

Performs data-flow slice analysis. Reads the srcML file and produces
a JSON file where each key is a variable identifier of the form
`varname-line-col-hash`. The `file` field inside each entry records
the path to the original source, which srcattributor uses in stage 3.
```bash
srcslice -i source.c.xml -o source.json
```

**Important:** srcslice records the path to `source.c.xml` inside
the JSON. srcattributor must be run from the same working directory,
and `source.c.xml` must remain at the same path. Do not use `/tmp`
as an intermediate location.

## Stage 3 — srcattributor

Merges slice data back into the srcML XML as `slice:decl` and
`slice:use` attributes. The `-o` output file must be the same filename
as the srcML from stage 1 — srcattributor resolves the srcML via the
path stored in the JSON.
```bash
srcattributor -i source.json -o source.c.xml
```

The `slice:decl` / `slice:use` attributes share a SHA1 hash that
links a variable's declaration site to every use site. This is what
allows the detector to trace from a dereference back to the original
NULL assignment.

## Stage 4 — detect_cwe476.py

Walks the annotated XML looking for `<expr>` nodes that carry a
`slice:use` attribute and match the smell pattern:

- `&` operator present
- `&&` operator absent  
- `->` operator present (dereference)
- `!=` operator present + `NULL` name present (null check)

The matching `slice:decl` node provides the declaration location and
initializer value for the note line.
```bash
python3 src/detect_cwe476.py source.c source.c.xml
```

## Namespace reference

| Prefix | URI | Purpose |
|---|---|---|
| `src` | `http://www.srcML.org/srcML/src` | structural elements |
| `pos` | `http://www.srcML.org/srcML/position` | line/col positions |
| `slice` | `http://www.srcML.org/srcML/slice` | data-flow attributes |
| `cpp` | `http://www.srcML.org/srcML/cpp` | preprocessor directives |