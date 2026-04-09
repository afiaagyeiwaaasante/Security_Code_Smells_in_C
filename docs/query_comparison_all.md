# Query / Detection Method Comparison — All Security Code Smells

This document consolidates the per-smell query comparison across all three tools:
**SmellDetect** (srcML + srcQL/Python), **cppcheck**, and **Joern** (CPG Scala queries).

Each smell's full detail is also available in `SCS00X_<Smell>/docs/query_comparison.md`.

---

## Summary Table

| SCS | Smell | CWE | SmellDetect query type | cppcheck trigger IDs | Joern query type | Our Recall | cpp Recall | Joern Recall |
|---|---|---|---|---|---|---|---|---|
| SCS001 | Dangerous Function Use | 242 | srcQL `CONTAINS gets($DEST)` | `getsCalled` | `cpg.call.name("gets")` | 100% | 100% | 100% |
| SCS002 | Buffer Size Mismatch | 680 | srcQL `CONTAINS malloc($A * $B)` | `integerOverflow`, `bufferOverflow` | `cpg.call.name("malloc").where(arg is multiply)` | 100% | 0% | 100% |
| SCS003 | Missing NULL Check | 476 | srcQL (6 detectors) | `nullPointer`, `bitwiseOnBoolean` | CPG null-assign tracking | 100% | 100% | 33% |
| SCS004 | Use-After-Free Risk | 416 | srcQL (7 detectors, `FOLLOWED BY`) | `deallocuse`, `deallocret` | CPG name-set difference | 100% | 75% | 75% |
| SCS005 | Memory Leak Pattern | 401 | srcQL + Python block filter | `memleak`, `resourceLeak` | CPG alloc/free set difference | 75% | 75% | 25% |
| SCS006 | Integer Overflow Risk | 190 | Python regex on srcML operators | `integerOverflow` (not emitted) | CPG arithmetic + MAX guard | 100% | 0% | 100% |
| SCS007 | Signed/Unsigned Confusion | 195 | Python regex `&gt;` in `<condition>` | `signConversion` (not emitted) | CPG method-level guard filter | 100% | 0% | 100% |
| SCS008 | Missing Format Specifier | 134 | Python regex arg-position literal check | `formatStringIsVararg` (not emitted) | CPG argument literal check | 100% | 0% | 100% |
| SCS009 | Command Injection Risk | 78 | Python regex taint-source list | `commandInjection` (not emitted) | CPG non-literal argument check | 60% | 0% | 100% |
| SCS010 | Hardcoded Sensitive Data | 259 | Python regex credential name + literal | `hardcodedPassword` (not emitted) | CPG name + literal traversal | 100% | 0% | 100% |

---

## SCS001 — Dangerous Function Use (CWE-242)

**Sinks:** `gets()`

### SmellDetect
```
srcQL: FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
XPath: //*[local-name()="call"]/*[local-name()="name"][.="gets"]/../@*[local-name()="start"]
```
Any match → finding. No guard check needed — `gets()` is unconditionally unsafe.

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: getsCalled
```

### Joern
```scala
val hits = cpg.call.name("gets").l
val detected = hits.nonEmpty
```

---

## SCS002 — Buffer Size Mismatch (CWE-680)

**Sinks:** `malloc(n * sizeof(T))`

### SmellDetect
```
srcQL: FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
XPath: //*[local-name()="call"]/*[local-name()="name"][.="malloc"]/../@*[local-name()="start"]
```
Matches malloc where the size argument is a product — the multiplication is the smell.

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: integerOverflow | bufferAccessOutOfBounds | bufferOverflow
```
Uses value-range analysis; misses cases where operand bounds are unknown.

### Joern
```scala
val hits = cpg.call.name("malloc")
  .where(_.argument.isCall.name("<operator>.multiplication"))
  .l
val detected = hits.nonEmpty
```

---

## SCS003 — Missing NULL Check (CWE-476)

**Patterns:** binary-if null test, deref before/after check, missing guard, interprocedural

### SmellDetect — 6 detectors

| Detector | srcQL Query |
|---|---|
| detect_binary_if | `FIND if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {}` |
| detect_check_after_deref | `FIND $T $FUNC() {} CONTAINS *$PTR FOLLOWED BY if($PTR != NULL) {}` |
| detect_deref_after_check | `FIND if($PTR == NULL) {} CONTAINS *$PTR` |
| detect_interprocedural | `FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR->$FIELD WHERE NOT (...) UNION ... DIFFERENCE ...` |
| detect_missing_guard | Parameterised helper |
| detect_null_deref | Parameterised helper |

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: nullPointer | nullPointerOutOfMemory | bitwiseOnBoolean | uninitvar
```

### Joern
```scala
// Pattern 1: NULL-assigned variable dereferenced
val nullPtrs = cpg.assignment.where(_.source.isLiteral.codeExact("0"))
  .target.isIdentifier.name.toSet
val derefHits = cpg.call
  .name("<operator>.indirectFieldAccess", "<operator>.indirectIndexAccess")
  .argument(1).isIdentifier.filter(i => nullPtrs.contains(i.name)).l

// Pattern 2: bitwise & in condition with pointer equality check
val bitwiseHits = cpg.call.name("<operator>.and")
  .where(_.argument.isCall.name("<operator>.notEquals", "<operator>.equals")).l

val detected = derefHits.nonEmpty || bitwiseHits.nonEmpty
```

---

## SCS004 — Use-After-Free Risk (CWE-416)

**Patterns:** free/use, new/delete, delete[], double free, return freed ptr, operator=, interprocedural

### SmellDetect — 7 detectors

| Detector | srcQL Query |
|---|---|
| detect_use_after_free | `FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)` |
| detect_new_delete_uaf | `FIND $T $FUNC() {} CONTAINS delete $PTR FOLLOWED BY $CALL($PTR)` |
| detect_delete_array_uaf | `FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL($PTR)` |
| detect_double_free | `FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY free($PTR)` |
| detect_return_freed_ptr | `FIND $RT $FNAME($PARAMS) {} CONTAINS free($PTR) FOLLOWED BY return $PTR` |
| detect_operator_equals_uaf | `FIND $RT operator=($PARAMS) {} CONTAINS delete[] $FIELD` |
| detect_interprocedural_uaf | `FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)` (+ delete variants) |

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: deallocuse | deallocret | operatorEqToSelf
```

### Joern
```scala
val freedVars = cpg.call.name("free", "delete", "<operator>.delete")
  .argument(1).isIdentifier.name.toSet
val hits = cpg.identifier.filter(i => freedVars.contains(i.name))
  .inCall.nameNot("free", "delete", "<operator>.delete").l
val detected = hits.nonEmpty
```
Name-based approximation — produces 3 FP on test suite due to scope reuse.

---

## SCS005 — Memory Leak Pattern (CWE-401)

**Patterns:** malloc without free, new without delete, overwrite leak

### SmellDetect — 3 detectors

| Detector | srcQL Query | Python Post-filter |
|---|---|---|
| detect_no_free_on_exit | `FIND $T $FUNC() {} CONTAINS malloc($SIZE)` | Check block for `<name>free</name>` |
| detect_new_no_delete | `FIND $T $FUNC() {} CONTAINS new $TYPE()` | Check block for `delete` element |
| detect_overwrite_leak | `FIND $T $FUNC() {} CONTAINS malloc($A) FOLLOWED BY malloc($B)` | Check for `free` between the two mallocs |

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: memleak | memleakOnRealloc | resourceLeak | autovarInvalidDeallocation
```

### Joern
```scala
val mallocVars = cpg.call.name("malloc", "calloc", "realloc")
  .inAssignment.target.isIdentifier.name.toSet
val freedVars = cpg.call.name("free").argument(1).isIdentifier.name.toSet
val leaked = mallocVars.diff(freedVars)
val detected = leaked.nonEmpty
```
Set difference — misses early-return paths and wrapper-freed pointers.

---

## SCS006 — Integer Overflow Risk (CWE-190/191)

**Operations:** `+`, `*`, `++`

### SmellDetect — 3 detectors (Python regex, no srcQL)

| Detector | Sink Pattern | Guard Pattern |
|---|---|---|
| detect_unchecked_add | `<operator … >\s*\+\s*</operator>` | `<name>INT_MAX\|CHAR_MAX\|…</name>` in `<condition>` |
| detect_unchecked_multiply | `<operator … >\s*\*\s*</operator>` | Same |
| detect_unchecked_increment | `<operator … >\s*\+\+\s*</operator>` | Same |

srcQL not used — it does not reliably match binary arithmetic operator patterns.

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: integerOverflow | signedIntegerOverflow | unsignedIntegerOverflow | integerOverflowCast
# Result: 0% recall — value-range analysis cannot bound fscanf-sourced values
```

### Joern
```scala
val arithOps = cpg.call.nameExact("<operator>.multiplication", "<operator>.addition",
  "<operator>.preIncrement", "<operator>.postIncrement")
val maxConstants = Set("INT_MAX","CHAR_MAX","SHRT_MAX","UINT_MAX","INT64_MAX","LLONG_MAX")
val guardedMethods = cpg.call
  .nameExact("<operator>.lessThan","<operator>.lessEqualsThan",
             "<operator>.greaterThan","<operator>.greaterEqualsThan")
  .argument.isIdentifier.filter(i => maxConstants.contains(i.name))
  .method.name.toSet
val hits = arithOps.filter(c => !guardedMethods.contains(c.method.name)).l
val detected = hits.nonEmpty
```
100% recall but 11 FP (50% precision) — over-broad guard check.

---

## SCS007 — Signed/Unsigned Confusion (CWE-195)

**Sinks:** `malloc`, `memcpy`, `memmove`, `strncpy`

### SmellDetect — 3 detectors (Python regex)

All three share the same guard logic:
```python
POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)
conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)
if any(POSITIVE_GUARD.search(c) for c in conditions):
    continue   # guard present
```
Sink patterns match `malloc`, `memcpy|memmove`, and `strncpy` respectively.

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: signConversion | negativeIndex | bufferAccessOutOfBounds | argumentSize
# Result: 0% recall — sign of fscanf return not tracked into size arguments
```

### Joern
```scala
val guardedMethods = cpg.call
  .nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan")
  .where(_.argument.isLiteral.filter(l => l.code == "0" || l.code == "1"))
  .method.name.toSet
val hits = cpg.call.nameExact("malloc", "memcpy", "memmove", "strncpy")
  .filter(c => !guardedMethods.contains(c.method.name)).l
val detected = hits.nonEmpty
```

---

## SCS008 — Missing Format Specifier (CWE-134)

**Sinks:** `printf`, `vprintf`, `fprintf`, `vfprintf`, `syslog`

### SmellDetect — 3 detectors (Python regex, argument-position check)

```python
# printf/vprintf: format = args[0]
# fprintf/vfprintf/syslog: format = args[1]
LITERAL_PAT = re.compile(r'<literal\b')
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
# If format argument contains no <literal> element → finding
```

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: invalidPrintfArgType | wrongPrintfScanfArgNum | formatStringIsVararg
# Result: 0% recall — these IDs cover type mismatches, not non-literal format args
```

### Joern
```scala
// printf/vprintf: argument.order(1) must be Literal
val printfBad = cpg.call.nameExact("printf", "vprintf")
  .filter(c => !c.argument.order(1).exists(_.isLiteral))
// fprintf/vfprintf/syslog: argument.order(2) must be Literal
val fprintfBad = cpg.call.nameExact("fprintf", "vfprintf", "syslog")
  .filter(c => !c.argument.order(2).exists(_.isLiteral))
val detected = (printfBad.l ++ fprintfBad.l).nonEmpty
```
Semantically identical to SmellDetect — same argument-position strategy, different representation.

---

## SCS009 — Command Injection Risk (CWE-78)

**Sinks:** `system`, `popen`, `execl`, `execlp`

### SmellDetect — 3 detectors (Python regex, taint-source list)

```python
INPUT_SOURCE = re.compile(r'<name[^>]*>\s*(?:fgets|getenv)\s*</name>')
LITERAL_PAT  = re.compile(r'<literal\b')
# Argument contains INPUT_SOURCE → tainted → finding
# Argument contains LITERAL_PAT  → safe → skip
# Neither → unknown → no finding (conservative)
```

Taint sources covered: `fgets`, `getenv`. Missing: `scanf`, `argv`, `getline` → 2 FN.

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: commandInjection | dangerousFunction | taintedData
# Result: 0% recall
```

### Joern
```scala
val systemPopenBad = cpg.call.nameExact("system", "popen")
  .filter(c => !c.argument.order(1).exists(_.isLiteral))
val execlBad = cpg.call.nameExact("execl", "execlp")
  .filter(c => !c.argument.order(1).exists(_.isLiteral))
val detected = (systemPopenBad.l ++ execlBad.l).nonEmpty
```
Non-literal = tainted (aggressive). Higher recall, potential false positives on safe computed strings.

---

## SCS010 — Hardcoded Sensitive Data (CWE-259)

**Patterns:** `#define` credential macros, variable string literals, `strcmp`/`strncmp`

### SmellDetect — 3 detectors (Python regex, credential name list)

```python
CRED_NAME = re.compile(
    r'(?i)(?:password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)'
)
```

| Detector | What it matches |
|---|---|
| detect_define_credential | `#define <CRED_NAME> "..."` |
| detect_password_literal | `char <cred_name>[] = "..."` or similar |
| detect_strcmp_hardcoded | `strcmp(x, "literal")` or `strcmp("literal", x)` |

### cppcheck
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file>
# Detects: [hardcodedCredentials] | [hardcodedPassword]
# Result: 0% recall — checker exists but not triggered on Juliet CWE-259 patterns
```

### Joern
```scala
val credPat = "(?i)(password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)".r
// 1. Local variable with credential name assigned a string literal
val varLiteral = cpg.local.filter(l => credPat.findFirstIn(l.name).isDefined)
  .filter(l => cpg.assignment.filter(a => a.target.code == l.name)
    .argument.order(2).isLiteral.nonEmpty)
// 2. strcmp/strncmp with any string literal argument
val strcmpHard = cpg.call.nameExact("strcmp", "strncmp")
  .filter(c => c.argument.isLiteral.nonEmpty)
val detected = (varLiteral.l ++ strcmpHard.l).nonEmpty
```
Same credential name list as SmellDetect. Strategy is equivalent across both tools.

---

## Cross-Tool Observations

### 1. cppcheck capability gaps
cppcheck achieves 0% recall on SCS006–SCS010. This is not a detection failure — these smell categories have no matching built-in checker in the tested version. The tool is capable on SCS001–SCS005 where appropriate checkers exist.

### 2. Query strategy alignment
SmellDetect and Joern independently arrive at structurally identical strategies for SCS007, SCS008, SCS009, and SCS010 — the same argument-position and guard-condition logic, expressed as XML regex vs. CPG traversal.

### 3. srcQL vs. Python regex
srcQL is used for SCS001–SCS005 where the smell is structural (call sequences, containment). Python regex is used for SCS006–SCS010 where the smell requires element-attribute inspection (operator text, argument types) that srcQL cannot reliably match.

### 4. Joern false positives
Joern's name-based set tracking (SCS004, SCS005) and over-broad guard checks (SCS006) produce false positives absent from SmellDetect. SmellDetect's structural guard scoping (per function block, per `<condition>` element) is more conservative.

### 5. Performance
| Tool | Avg wall time | Avg peak RSS |
|---|---|---|
| SmellDetect | ~0.30s | ~15 MB |
| cppcheck | ~0.01s | ~8 MB |
| Joern | ~3.70s | ~420 MB |

Joern's JVM startup and CPG construction dominate its runtime. SmellDetect is competitive on accuracy at 1/12 of Joern's resource cost.
