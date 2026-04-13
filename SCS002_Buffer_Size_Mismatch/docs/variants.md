# SCS002 — Query Variants and Extension Points

The current detector uses:

```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
```

The same pattern extends to other allocation functions and related overflow risks.

---

## Variants coverable with this query style

| Pattern | Risk | srcQL variant |
|---------|------|---------------|
| `malloc(n * sizeof(T))` | Integer overflow → small allocation | `CONTAINS malloc($A * $B)` ✓ Detector 1 |
| `sz = n * sizeof(T); malloc(sz)` | Overflow in precomputed size variable | `CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)` ✓ Detector 2 |
| `realloc(p, n * sizeof(T))` | Same overflow risk on resize | `CONTAINS realloc($PTR, $A * $B)` |
| `alloca(n * sizeof(T))` | Stack allocation overflow | `CONTAINS alloca($A * $B)` |
| `memset(p, 0, n * sizeof(T))` | Overflow in count passed to memset | `CONTAINS memset($P, $V, $A * $B)` |
| `memcpy(dst, src, n * sizeof(T))` | Overflow in copy length | `CONTAINS memcpy($D, $S, $A * $B)` |

---

## Tightening the query with sizeof

To reduce false positives from constant multiplication (e.g. `malloc(2 * 4)`),
the query can be restricted to cases where one operand is a `sizeof` expression.
In srcQL this can be expressed as:

```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * sizeof($TYPE))
```

This matches only `malloc(n * sizeof(SomeType))`, excluding pure numeric
literals.

---

## UNION query for multiple allocation functions

```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
UNION
FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)
UNION
FIND $T $FUNC($PARAMS) {} CONTAINS realloc($PTR, $A * $B)
UNION
FIND $T $FUNC($PARAMS) {} CONTAINS memcpy($DST, $SRC, $A * $B)
```

---

## Variants not coverable with this query style

| Scenario | Why the current pattern does not apply |
|----------|----------------------------------------|
| Overflow in a function argument passed to malloc wrapper | Requires interprocedural analysis beyond what srcQL `FOLLOWED BY` provides |
| Signed integer overflow (`int n` instead of `size_t n`) | The query matches the structural pattern but does not distinguish signed from unsigned overflow — requires type analysis |
