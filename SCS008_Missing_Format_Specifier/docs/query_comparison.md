# SCS008 — Query / Detection Method Comparison

**Smell:** Missing Format Specifier
**CWE:** CWE-134 (Use of Externally-Controlled Format String), CWE-686
**Sinks covered:** `printf`, `vprintf`, `fprintf`, `vfprintf`, `syslog`

---

## SmellDetect

**Mechanism:** srcML XML annotation + Python regex (argument position check)

Three detectors, each targeting a sink group:

### detect_printf_direct.sh

**Sink pattern (Python regex):**
```python
PRINTF_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*(?:printf|vprintf)\s*</name>',
    re.DOTALL
)
```

**Argument patterns:**
```python
LITERAL_PAT = re.compile(r'<literal\b')
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
```

**Logic:** For each `printf`/`vprintf` call, split the argument list and check whether the **first argument** contains a `<literal>` element (a string literal format). If the first argument is not a literal → finding emitted (format string is a variable).

### detect_fprintf_direct.sh

Same logic for `fprintf`/`vfprintf`/`syslog`. The format argument is at **position 2** (after the file descriptor/priority argument), so `args[1]` is checked.

### detect_syslog_direct.sh

Same as `fprintf` — format is the second argument after the priority level.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
invalidPrintfArgType | wrongPrintfScanfArgNum | formatStringIsVararg | invalidScanfArgType
```

**Result on test suite:** 0% recall. These IDs relate to format string type mismatches and argument count errors, not to the case where the format string itself is a non-literal variable. `formatStringIsVararg` is the closest match but was not emitted on the Juliet patterns.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

// printf/vprintf: format is argument at position 1
val printfBad = cpg.call
  .nameExact("printf", "vprintf")
  .filter { c =>
    val fmt = c.argument.order(1).l
    fmt.nonEmpty && !fmt.exists(_.isLiteral)
  }

// fprintf/vfprintf/syslog: format is argument at position 2
val fprintfBad = cpg.call
  .nameExact("fprintf", "vfprintf", "syslog")
  .filter { c =>
    val fmt = c.argument.order(2).l
    fmt.nonEmpty && !fmt.exists(_.isLiteral)
  }

val detected = (printfBad.l ++ fprintfBad.l).nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Checks whether the format argument (by position) is a CPG `Literal` node. If not → detected. Semantically identical to SmellDetect's argument-position check but expressed as CPG node type filtering.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | Python regex arg-position check | Type/count analysis | CPG argument literal check |
| Format arg position | Hardcoded per sink (1 or 2) | Implicit | Hardcoded per sink (order 1 or 2) |
| Recall | 100% | 0% | 100% |
| Precision | 100% | N/A | 100% |
| Equivalent strategy | Yes — same as Joern | No | Yes — same as SmellDetect |
