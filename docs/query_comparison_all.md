# Query / Detection Method Comparison — All Security Code Smells

This document consolidates the per-smell query comparison across all three tools:
**SmellDetect** (srcML + srcQL/XPath), **cppcheck**, and **Joern** (CPG Scala queries).

Each smell's full detail is also available in `SCS00X_<Smell>/docs/query_comparison.md`.

---

## Summary Table

| SCS | Smell | CWE | SmellDetect query type | cppcheck trigger IDs | Joern query type | Our Recall | Our Precision | cpp Recall | Joern Recall | Joern Precision |
|---|---|---|---|---|---|---|---|---|---|---|
| SCS001 | Dangerous Function Use | 242 | srcQL `CONTAINS gets($DEST)` | `getsCalled` | `cpg.call.name("gets")` | 100% | 100% | 100% | 100% | 100% |
| SCS002 | Buffer Size Mismatch | 680 | srcQL `CONTAINS malloc($A * $B)` | `integerOverflow`, `bufferOverflow` | `cpg.call.name("malloc").where(arg is multiply)` | 100% | 100% | 0% | 87.5% | 63.6% |
| SCS003 | Missing NULL Check | 476 | srcQL (6 detectors) | `nullPointer`, `bitwiseOnBoolean` | CPG null-assign tracking | 100% | 75% | 100% | 33.3% | 100% |
| SCS004 | Use-After-Free Risk | 416 | srcQL (7 detectors, `FOLLOWED BY`) | `deallocuse`, `deallocret` | CPG name-set difference | 100% | 100% | 75% | 75% | 50% |
| SCS005 | Memory Leak Pattern | 401 | srcQL + XPath block filter | `memleak`, `resourceLeak` | CPG alloc/free set difference | 75% | 100% | 75% | 25% | 100% |
| SCS006 | Integer Overflow Risk | 190 | srcQL + XPath `count(MAX-constant in condition)` | `integerOverflow` (not emitted) | CPG arithmetic + MAX guard | 100% | 100% | 0% | 100% | 50% |
| SCS007 | Signed/Unsigned Confusion | 195 | srcQL + XPath `count(> guard in condition)` | `signConversion` (not emitted) | CPG method-level guard filter | 100% | 100% | 0% | 100% | 100% |
| SCS008 | Missing Format Specifier | 134 | srcQL scope + XPath literal check + taint count | `formatStringIsVararg` (not emitted) | CPG argument literal check | 100% | 100% | 0% | 100% | 100% |
| SCS009 | Command Injection Risk | 78 | srcQL scope + XPath literal check + taint count | `commandInjection` (not emitted) | CPG non-literal argument check | 60% | 100% | 0% | 100% | 100% |
| SCS010 | Hardcoded Sensitive Data | 259 | XPath credential name + literal check | `hardcodedPassword` (not emitted) | CPG name + literal traversal | 100% | 100% | 0% | 60% | 100% |

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
87.5% recall, 63.6% precision — 4 FP from precomputed-size patterns where multiplication happens before the `malloc` call.

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

100% recall, 75% precision — 1 FP from an edge-case bitwise pattern.

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
33.3% recall — misses missing-guard and interprocedural patterns that require flow reasoning.

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
75% recall, 50% precision — 3 FP from name reuse across scopes.

---

## SCS005 — Memory Leak Pattern (CWE-401)

**Patterns:** malloc without free, new without delete, overwrite leak

### SmellDetect — 3 detectors

| Detector | srcQL Query | XPath Post-filter |
|---|---|---|
| detect_no_free_on_exit | `FIND $T $FUNC() {} CONTAINS malloc($SIZE)` | Check block for `<name>free</name>` |
| detect_new_no_delete | `FIND $T $FUNC() {} CONTAINS new $TYPE()` | Check block for `delete` element |
| detect_overwrite_leak | `FIND $T $FUNC() {} CONTAINS malloc($A) FOLLOWED BY malloc($B)` | Check for `free` between the two mallocs |

75% recall — 1 FN from an early-return path where free is conditional.

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
25% recall — set difference misses early-return paths and wrapper-freed pointers.

---

## SCS006 — Integer Overflow Risk (CWE-190/191)

**Operations:** `+`, `*`, `++`

### SmellDetect — 3 detectors (srcQL + XPath, no Python)

| Detector | Sink (srcQL) | Guard (XPath) |
|---|---|---|
| detect_unchecked_multiply | `FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A * $B` | `count(<condition>[<name>=INT_MAX/CHAR_MAX/…])` = 0 |
| detect_unchecked_add | `FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A + $B` | Same |
| detect_unchecked_increment | XPath only: `//*[local-name()='operator'][.='++'][ancestor::function[not(condition/name=MAX)]]` | No srcQL — standalone `++` not matchable |

Destructor/constructor blocks use an `ancestor::` XPath fallback since srcQL requires a return type.

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
100% recall, 50% precision — over-broad guard check produces 11 FP (flags all arithmetic in functions that happen to contain a MAX comparison, even if unrelated).

---

## SCS007 — Signed/Unsigned Confusion (CWE-195)

**Sinks:** `malloc`, `memcpy`, `memmove`, `strncpy`

### SmellDetect — 3 detectors (srcQL + XPath, no Python)

| Detector | Sink (srcQL) | Guard (XPath) |
|---|---|---|
| detect_signed_malloc | `FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A)` | `count(<condition>[<operator>=>])` = 0 |
| detect_signed_memcpy | `FIND $T $FUNC($PARAMS) {} CONTAINS memcpy($A,$B,$C)` (and memmove) | Same `>` guard |
| detect_signed_strncpy | `FIND $T $FUNC($PARAMS) {} CONTAINS strncpy($A,$B,$C)` | Same `>` guard |

Destructor/constructor blocks use an `ancestor::` XPath fallback.

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
100% recall, 100% precision on the test suite.

---

## SCS008 — Missing Format Specifier (CWE-134)

**Sinks:** `printf`, `vprintf`, `fprintf`, `vfprintf`, `syslog`

### SmellDetect — 3 detectors (srcQL + XPath + taint co-occurrence, no Python)

All three share the same two-stage structure:

**Stage 1 — srcQL (function scope):**
```
FIND $T $FUNC($PARAMS) {} CONTAINS printf($FMT)   # or fprintf / syslog
```

**Stage 1 guard — XPath on srcQL result:**
```xpath
-- Part 1: format arg is non-literal (printf: arg 1; fprintf/syslog: arg 2) --
//*[local-name()='call'][*[local-name()='name'][.='printf' or .='vprintf']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]

-- Part 2: taint source present in same function --
count(//*[local-name()='call'][*[local-name()='name']
  [.='fgets' or .='getenv' or .='scanf' or .='fscanf']])
```

**Stage 2 — XPath fallback for `<destructor>`/`<constructor>`:** uses `ancestor::` predicate with the same taint source co-occurrence check.

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
Semantically identical to SmellDetect's literal check — same argument-position strategy. No taint co-occurrence requirement, so it also catches cross-block and cross-file cases. 100% recall, 100% precision on test suite.

---

## SCS009 — Command Injection Risk (CWE-78)

**Sinks:** `system`, `popen`, `execl`, `execlp`

### SmellDetect — 3 detectors (srcQL + XPath + taint co-occurrence, no Python)

All three share the same two-stage structure as SCS008:

**Stage 1 — srcQL (function scope):**
```
FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)   # or popen / execl / execlp
```

**Stage 1 guard — XPath on srcQL result:**
```xpath
-- Part 1: command arg is non-literal --
//*[local-name()='call'][*[local-name()='name'][.='system']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]

-- Part 2: taint source present in same function --
count(//*[local-name()='call'][*[local-name()='name']
  [.='fgets' or .='getenv']])
```

**Stage 2 — XPath fallback for `<destructor>`/`<constructor>`:** same `ancestor::` structure.

60% recall — 2 FN: interprocedural sink file (no taint source visible) and C++ class cross-block (fgets in constructor, system in destructor).

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
No taint co-occurrence requirement — any non-literal first argument is flagged. 100% recall, 100% precision on test suite (catches the 2 cases SmellDetect misses: interprocedural sink and C++ class cross-block).

---

## SCS010 — Hardcoded Sensitive Data (CWE-259)

**Patterns:** `#define` credential macros, variable string literals, `strcmp`/`strncmp`

### SmellDetect — 3 detectors (pure XPath, no Python, no srcQL)

XPath `translate()` provides case-insensitive keyword matching without Python regex.

| Detector | XPath Pattern |
|---|---|
| detect_define_credential | `<define>[macro/name contains cred keyword][value starts-with '"']` |
| detect_password_literal | `<decl>[name contains cred keyword][init has string literal, no call]` + `strcpy` fallback |
| detect_strcmp_hardcoded | `<call>[strcmp/strncmp][any argument has string literal]` |

```xpath
-- Credential keyword check (case-insensitive via translate()) --
contains(translate(*[local-name()='name'],
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),
  'password') or contains(...,'passwd') or ...
```

100% recall, 100% precision on test suite.

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
60% recall, 100% precision — 2 FN: `#define` macros (expanded before CPG build, so the `<define>` node doesn't exist in the CPG) and C++ class member assignment (not captured by the local variable traversal). SmellDetect's XPath `<define>` check directly queries the pre-preprocessed srcML representation, giving it an advantage here.

---

## Cross-Tool Observations

### 1. cppcheck capability gaps
cppcheck achieves 0% recall on SCS006–SCS010. This is not a detection failure — these smell categories have no matching built-in checker in the tested version. The tool is capable on SCS001–SCS005 where appropriate checkers exist.

### 2. Query strategy alignment
SmellDetect and Joern independently arrive at structurally identical strategies for SCS007, SCS008, SCS009, and SCS010 — the same argument-position and guard-condition logic, expressed as XPath predicates vs. CPG traversal. The differences in recall trace to taint co-occurrence requirements (SCS008/SCS009) and representation gaps (SCS010 `#define` nodes).

### 3. srcQL vs. XPath split
srcQL is used for SCS001–SCS009 where the smell is structural (call sequences, containment, function scope). srcQL **cannot** be used for SCS010 for two structural reasons: (1) `#define` macro declarations exist outside any function body, so the `FIND $T $FUNC() {} CONTAINS ...` form has nothing to match against; (2) credential keyword detection requires case-insensitive substring matching (`translate()`) which srcQL's pattern syntax does not support. Pure XPath is the only viable mechanism for SCS010. All detectors are Python-free.

### 4. Taint co-occurrence: precision vs. recall trade-off
SCS008 and SCS009 require a taint source (`fgets`, `getenv`, `scanf`, `fscanf`) to be present in the same function block as the sink. This improves precision (fewer false positives on safe computed strings) at the cost of recall on cross-block and cross-file taint flows. Joern applies no taint co-occurrence check and achieves higher recall on those patterns.

### 5. SCS010: SmellDetect outperforms Joern
SCS010 is the only smell where SmellDetect (100% recall) outperforms Joern (60% recall). Joern's CPG operates on post-preprocessed code — `#define` macros are expanded and lost. SmellDetect's srcML XML preserves the `<define>` element, making the macro credential pattern directly queryable.

### 6. Joern false positives
Joern's name-based set tracking (SCS004, SCS005) and over-broad guard checks (SCS006) produce false positives absent from SmellDetect. SmellDetect's structural guard scoping (per function block, per `<condition>` element) is more conservative.

### 7. Performance
| Tool | Avg wall time | Avg peak RSS |
|---|---|---|
| SmellDetect | ~0.30s | ~15 MB |
| cppcheck | ~0.01s | ~8 MB |
| Joern | ~3.60s | ~420 MB |

Joern's JVM startup and CPG construction dominate its runtime. SmellDetect achieves competitive accuracy at ~1/12 of Joern's resource cost.
