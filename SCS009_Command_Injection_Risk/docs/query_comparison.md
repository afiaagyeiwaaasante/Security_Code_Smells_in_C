# SCS009 — Query / Detection Method Comparison

**Smell:** Command Injection Risk
**CWE:** CWE-78 (Improper Neutralisation of Special Elements in OS Commands), CWE-88
**Sinks covered:** `system`, `popen`, `execl`, `execlp`

---

## SmellDetect

**Mechanism:** srcML XML annotation + Python regex (taint-source + literal check)

Three detectors, each targeting one sink group:

### detect_system_tainted.sh

**Sink pattern (Python regex):**
```python
SYSTEM_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*system\s*</name>(.*?)</call>',
    re.DOTALL
)
```

**Safe / taint-source patterns:**
```python
LITERAL_PAT  = re.compile(r'<literal\b')
INPUT_SOURCE = re.compile(
    r'<name[^>]*>\s*(?:fgets|getenv)\s*</name>'
)
```

**Logic:** For each `system()` call, check the argument content:
- If the argument contains a `<literal>` → safe (hardcoded command), no finding.
- If the argument contains a call to a taint source (`fgets`, `getenv`) → finding emitted.
- If neither → no finding (unknown origin, conservative).

### detect_popen_tainted.sh / detect_execl_tainted.sh

Same logic for `popen()` and `execl()`/`execlp()`. `execl` checks argument at position 1.

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
| Query type | Python regex + taint-source list | Taint analysis | CPG literal argument check |
| Taint sources tracked | `fgets`, `getenv` | None detected | Any non-literal |
| Recall | 60% (2 FN on unlisted sources) | 0% | 100% (by over-approximation) |
| Precision | 100% | N/A | Not measured (0 FP on test suite) |
| Conservative vs aggressive | Conservative | — | Aggressive |
