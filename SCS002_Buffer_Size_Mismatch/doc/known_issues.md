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

## 4. Multiplication hidden in a variable is not detected

**Issue:** If the multiplication happens before the malloc call and is stored
in a variable, the query will not match.

**Example:**
```c
size_t sz = n * sizeof(int);   /* overflow happens here */
p = malloc(sz);                /* query does not match — no * in malloc arg */
```

Detecting this pattern requires data flow analysis (taint tracking from the
multiplication to the malloc argument).

---

## 5. sizeof in the query is matched structurally

**Issue:** The query uses `$B` to match the second operand of the
multiplication. It does not enforce that `$B` is a `sizeof` expression.
Patterns like `malloc(n * 4)` are also flagged, even though the literal `4`
cannot overflow by itself.
