# SCS002 — Known Issues and Limitations

## 1. Constant multiplication is a false positive

**Issue:** The query `CONTAINS malloc($A * $B)` matches any multiplication in
the malloc argument, including constant expressions that cannot overflow.

**Example:**
```c
p = malloc(2 * sizeof(int));   /* flagged — but 2 * sizeof(int) is a constant, safe */
```

**Workaround:** The note message directs the developer to review whether `$A`
is a runtime variable. A future improvement could use data flow analysis to
exclude cases where both operands are compile-time constants.

---

## 2. Only one finding emitted per translation unit

**Issue:** The detector uses `head -1` when extracting call position, so only
the first `malloc(... * ...)` call is reported even if a function contains
multiple such calls.

---

## 3. realloc and calloc with multiplied arguments not covered

**Issue:** The same overflow risk applies to `realloc(p, n * sizeof(T))` but
the current query only covers `malloc`. `calloc(n, sizeof(T))` is the safe
replacement and is intentionally excluded from detection.

---

## ~~4. Multiplication hidden in a variable is not detected~~ — RESOLVED

**Previously:** If the multiplication happened before the malloc call and was
stored in a variable, the `malloc($A * $B)` query would not match.

**Example:**
```c
size_t sz = n * sizeof(int);   /* overflow happens here */
p = malloc(sz);                /* no * in malloc arg — missed by detector 1 */
```

**Fix:** Added a second detector `detect_precomputed_size.sh` using the query:
```
FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)
```
This matches the declaration of the intermediate size variable and traces it
to the `malloc()` call via the `FOLLOWED BY` clause.

The detector includes the same `SIZE_MAX` guard filter — if an `if` condition
containing `SIZE_MAX` precedes the `malloc()` call, the finding is suppressed.

**Verified by:**

| Test case | Scenario | Expected | Result |
|---|---|---|---|
| `bad_malloc_precomputed_01.c` | `sz = n * sizeof(int); malloc(sz)` | FOUND | FOUND ✓ |
| `good_malloc_precomputed_01.c` | same pattern with `SIZE_MAX` guard | MISSED | MISSED ✓ |

---

## 5. sizeof in the query is matched structurally

**Issue:** The query uses `$B` to match the second operand of the
multiplication. It does not enforce that `$B` is a `sizeof` expression.
Patterns like `malloc(n * 4)` are also flagged, even though the literal `4`
cannot overflow by itself.

---

## ~~6. Explicit overflow guard before malloc is a false positive~~ — RESOLVED

**Previously:** When a developer guarded the malloc with an explicit `SIZE_MAX`
overflow check, the `malloc($A * $B)` pattern was still flagged even though the
code was safe.

**Fix:** Both detectors now run a Python post-filter that scans source lines
before the malloc call for an `if.*SIZE_MAX` pattern. If a guard is found,
the finding is suppressed.

```python
guard_pat = re.compile(r'\bif\b.*SIZE_MAX')
for line in lines[:call_line]:
    if guard_pat.search(line):
        # suppress finding
```

**Verified by:** All 4 `good_malloc_*_guarded.c` test cases — MISSED (correct, 0 FP).

**Note:** Joern does **not** implement this guard filter and flags all 4 guarded
cases as findings (4 FPs in the evaluation).

---

## 7. ~~Struct-member and interprocedural size values are false negatives~~ — INCORRECT

**Previously documented as:** struct field access (`ctx.count * sizeof(int)`) and
return-value interprocedural cases would be missed.

**Actual behaviour (confirmed by evaluation):** Both are **detected**.

- `malloc(ctx.count * sizeof(int))` — the srcQL metavariable `$A` binds to
  `ctx.count` (a struct member expression) as well as plain variables. The
  multiplication is still structurally present inside the malloc argument.
- `int data = get_size(); malloc(data * sizeof(int))` — `data` is a plain local
  variable at the call site regardless of how it was assigned. The pattern matches.

The genuine false negative for this smell is only the precomputed case
(`sz = n * sizeof(T); malloc(sz)`) — now covered by Detector 2 (Issue 4, RESOLVED).

**Test cases:** `testsuites/CWE680/struct/bad_malloc_struct_01.c` — FOUND ✓
`testsuites/CWE680/interprocedural/bad_malloc_return_01.c` — FOUND ✓
