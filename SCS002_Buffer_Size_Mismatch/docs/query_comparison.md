# SCS002 — Query / Detection Method Comparison

**Smell:** Buffer Size Mismatch
**CWE:** CWE-680 (Integer Overflow to Buffer Overflow)
**Sinks covered:** `malloc(n * sizeof(T))` and `size_t sz = n * sizeof(T); malloc(sz)`

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural query + Python guard filter

### Detector 1 — `buffer_size_mismatch`

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
```

Matches any function containing a `malloc()` call whose size argument is a
product expression. `$A` binds to the first operand (typically a count variable).

**Guard filter (Python):**
After the srcQL match, scans source lines before the call for a `SIZE_MAX`
guard condition. If `if.*SIZE_MAX` is found, the finding is suppressed.

```python
guard_pat = re.compile(r'\bif\b.*SIZE_MAX')
for line in lines[:call_line]:
    if guard_pat.search(line):
        # suppress — explicit overflow check already present
```

### Detector 2 — `precomputed_size`

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)
```

Matches functions where a variable is assigned a product and that variable is
then passed directly to `malloc()`. Catches the pattern where the overflow risk
is at the assignment, not inside the malloc call itself.

Applies the same `if.*SIZE_MAX` guard filter as Detector 1.

**XPath (position extraction, both detectors):**
```xpath
//*[local-name()="call"]/*[local-name()="name"][.="malloc"]/../@*[local-name()="start"]
```

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
integerOverflow | bufferAccessOutOfBounds | bufferOverflow
```

**Notes:** cppcheck requires value-range analysis to infer that the product can
overflow. With unknown operand bounds (e.g. a value from `rand()` or `fgets()`),
it cannot determine overflow is possible and emits no finding.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")
val hits = cpg.call.name("malloc")
  .where(_.argument.isCall.name("<operator>.multiplication"))
  .l
val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Finds `malloc` call nodes whose argument subtree contains a
multiplication operator node. Purely structural — no guard filter, no value-range
analysis.

---

## Evaluation Results (19 test cases)

| Test Case | Expected | SmellDetect | cppcheck | Joern |
|-----------|----------|-------------|----------|-------|
| bad_malloc_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| good_malloc_01_guarded | MISSED | MISSED ✓ | MISSED ✓ | **FOUND ✗ (FP)** |
| bad_malloc_fixed_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_fixed_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| good_malloc_fixed_01_guarded | MISSED | MISSED ✓ | MISSED ✓ | **FOUND ✗ (FP)** |
| bad_malloc_fgets_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_fgets_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| good_malloc_fgets_01_guarded | MISSED | MISSED ✓ | MISSED ✓ | **FOUND ✗ (FP)** |
| bad_malloc_rand_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_rand_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| good_malloc_rand_01_guarded | MISSED | MISSED ✓ | MISSED ✓ | **FOUND ✗ (FP)** |
| bad_malloc_precomputed_01 | FOUND | FOUND ✓ | MISSED | **MISSED ✗ (FN)** |
| good_malloc_precomputed_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| bad_malloc_return_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_interproc_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |
| bad_malloc_interproc_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| bad_malloc_struct_01 | FOUND | FOUND ✓ | MISSED | FOUND ✓ |
| good_malloc_struct_01 | MISSED | MISSED ✓ | MISSED ✓ | MISSED ✓ |

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|--------|-------------|----------|-------|
| Query type | srcQL structural + Python guard filter | Value-range analysis | CPG structural query |
| Guard check | Yes — `if.*SIZE_MAX` filter suppresses safe patterns | Implicit (value range) | No |
| Precomputed size (`sz = n*s; malloc(sz)`) | Yes — Detector 2 | No | No (FN) |
| Interprocedural | Yes (multi-file archive) | Partial | Yes (directory import) |
| True Positives | 8 | 0 | 7 |
| True Negatives | 11 | 11 | 7 |
| False Positives | 0 | 0 | 4 |
| False Negatives | 0 | 8 | 1 |
| Precision | 100% | N/A | 63.6% |
| Recall | 100% | 0% | 87.5% |
