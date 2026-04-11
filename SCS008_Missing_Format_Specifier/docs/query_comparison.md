# SCS008 — Query / Detection Method Comparison

**Smell:** Missing Format Specifier
**CWE:** CWE-134 (Use of Externally-Controlled Format String), CWE-686
**Sinks covered:** `printf`, `vprintf`, `fprintf`, `vfprintf`, `syslog`

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL (function scope) + XPath (argument literal check + taint count)

Three detectors share the same two-stage structure:

### detect_printf_direct.sh / detect_fprintf_direct.sh / detect_syslog_direct.sh

**Stage 1 — srcQL (function scope):**
```
FIND $T $FUNC($PARAMS) {} CONTAINS printf($FMT)   # or fprintf / syslog
```

**Stage 1 guard — XPath on srcQL result:**

Non-literal format argument check (printf: arg 1; fprintf/syslog: arg 2):
```xpath
//*[local-name()='call'][*[local-name()='name'][.='printf' or .='vprintf']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
/@*[local-name()='start']
```

Taint source check (flat count — srcQL result is already function-scoped):
```xpath
count(//*[local-name()='call'][*[local-name()='name']
  [.='fgets' or .='getenv' or .='scanf' or .='fscanf']])
```

A finding is emitted only when both hold: non-empty position AND count > 0.

**Stage 2 — XPath fallback for `<destructor>`/`<constructor>`:**

srcQL does not match C++ destructor/constructor blocks. An `ancestor::` predicate on the original XML covers these cases (taint source must also be present in the same destructor/constructor block):
```xpath
//*[local-name()='call'][*[local-name()='name'][.='printf' or .='vprintf']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
  [ancestor::*[local-name()='destructor' or local-name()='constructor']
    [.//*[local-name()='call'][*[local-name()='name']
      [.='fgets' or .='getenv' or .='scanf' or .='fscanf']]]]
```

**Known limitation:** Cross-block taint (fgets in constructor, printf in destructor) and cross-file taint (interprocedural) are not detected — documented as KI-002 and KI-001 respectively.

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

**Detection logic:** Checks whether the format argument (by position) is a CPG `Literal` node. If not → detected. No taint source check — any non-literal format argument is flagged regardless of whether user input is present. Higher recall than SmellDetect on cross-block and interprocedural cases.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL function scope + XPath literal/taint guard | Type/count analysis | CPG argument literal check |
| Format arg position | Hardcoded per sink (1 or 2) | Implicit | Hardcoded per sink (order 1 or 2) |
| Taint co-occurrence | Required (fgets/getenv/scanf/fscanf) | None | None |
| Recall | 60% (2 FN: cpp_class cross-block, interprocedural) | 0% | 100% |
| Precision | Higher (taint guard suppresses non-user-input cases) | N/A | Lower (flags any non-literal) |
