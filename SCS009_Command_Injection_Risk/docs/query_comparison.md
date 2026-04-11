# SCS009 — Query / Detection Method Comparison

**Smell:** Command Injection Risk
**CWE:** CWE-78 (Improper Neutralisation of Special Elements in OS Commands), CWE-88
**Sinks covered:** `system`, `popen`, `execl`, `execlp`

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL (function scope) + XPath (argument literal check + taint count)

Three detectors share the same two-stage structure:

### detect_system_tainted.sh / detect_popen_tainted.sh / detect_execl_tainted.sh

**Stage 1 — srcQL (function scope):**
```
FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)   # or popen / execl / execlp
```

**Stage 1 guard — XPath on srcQL result:**

Non-literal argument check:
```xpath
//*[local-name()='call'][*[local-name()='name'][.='system']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
/@*[local-name()='start']
```

Taint source check (flat count — srcQL result is already function-scoped):
```xpath
count(//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']])
```

A finding is emitted only when both hold: non-empty position AND count > 0.

**Stage 2 — XPath fallback for `<destructor>`/`<constructor>`:**

srcQL requires a return type and does not match C++ destructor/constructor blocks. An `ancestor::` predicate on the original XML covers these cases:
```xpath
//*[local-name()='call'][*[local-name()='name'][.='system']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
  [ancestor::*[local-name()='destructor' or local-name()='constructor']
    [.//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']]]]
```

**Logic:**
- srcQL narrows the XML to the matching function body, so the taint source check becomes a simple `count()` rather than an `ancestor::` predicate.
- The `ancestor::` predicate is still used in Stage 2 because there is no srcQL-scoped result to work with for destructors/constructors.

### detect_execl_tainted.sh

**Strategy (srcQL + XPath, not pure XPath):**

srcQL scopes to the function body first:
```
FIND $T $FUNC($PARAMS) {} CONTAINS execl($PATH)
FIND $T $FUNC($PARAMS) {} CONTAINS execlp($PATH)
```

XPath guard applied to the srcQL result (already function-scoped):
```xpath
//*[local-name()='call'][*[local-name()='name'][.='execl' or .='execlp']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
/@*[local-name()='start']
```

Taint source check (flat count on result, no `ancestor::` needed):
```xpath
count(//*[local-name()='call'][*[local-name()='name'][.='fgets' or .='getenv']])
```

A destructor/constructor XPath fallback covers C++ class bodies not matched by srcQL.

**Known limitation:** Only `fgets` and `getenv` are recognised as taint sources. Other sources (`scanf`, `argv`, `getline`) are not currently covered, producing false negatives on those flow variants.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
commandInjection | dangerousFunction | taintedData | useInputInFunctionCall
```

**Result on test suite:** 0% recall. cppcheck does not perform inter-statement taint tracking for `system()`/`popen()` in its default mode. None of the above message IDs were emitted on the Juliet CWE-78 patterns.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

// system/popen: argument 1 must be a literal to be safe
val systemPopenBad = cpg.call
  .nameExact("system", "popen")
  .filter { c =>
    val arg = c.argument.order(1).l
    arg.nonEmpty && !arg.exists(_.isLiteral)
  }

// execl/execlp: first argument (path) must be a literal
val execlBad = cpg.call
  .nameExact("execl", "execlp")
  .filter { c =>
    val arg = c.argument.order(1).l
    arg.nonEmpty && !arg.exists(_.isLiteral)
  }

val detected = (systemPopenBad.l ++ execlBad.l).nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** A call is flagged if its first argument is not a CPG `Literal` node. This is a conservative over-approximation — any non-literal argument (including safe computed strings) will be flagged.

**Comparison with SmellDetect:** Joern's check is simpler (non-literal = tainted) whereas SmellDetect explicitly looks for known taint sources. Joern has higher recall but potentially higher false positive rate on code with safe non-literal arguments.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL function scope + XPath literal/taint guard | Taint analysis | CPG literal argument check |
| Taint sources tracked | `fgets`, `getenv` | None detected | Any non-literal |
| Recall | 60% (2 FN on unlisted sources) | 0% | 100% (by over-approximation) |
| Precision | 100% | N/A | Not measured (0 FP on test suite) |
| Conservative vs aggressive | Conservative | — | Aggressive |
