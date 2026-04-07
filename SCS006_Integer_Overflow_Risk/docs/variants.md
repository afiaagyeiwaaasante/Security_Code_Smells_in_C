# SCS006 — CWE-190 Variants and Coverage

## Overview

CWE-190 (Integer Overflow or Wraparound) describes integer arithmetic operations
that produce a result exceeding the type's representable range. The test suite
covers seven operation scenarios across multiple data types and three C++ class
dispatch patterns.

## Scenarios

### S01 — Addition (`+`)

Addition of two integers where the sum can exceed `TYPE_MAX`.

| Type          | Bad file                     | Good file                     |
|---------------|------------------------------|-------------------------------|
| `char`        | `add/bad_char_add_01.c`      | `add/good_char_add_01.c`      |
| `unsigned int`| `add/bad_unsigned_int_add_01.c` | `add/good_unsigned_int_add_01.c` |

**Bad pattern:** `char result = data + 1;` with no `CHAR_MAX` check.
**Good pattern:** `if (data < CHAR_MAX) { ... }` guards the operation.

**Edge case:** `bad_unsigned_int_add_01` initialises `data = UINT_MAX` (a `<decl>`
initialiser), then adds 1. The `UINT_MAX` constant appears outside any
`<condition>` element, so the detector correctly reports a finding.

---

### S02 — Multiplication (`*`)

Multiplication where the product can exceed `TYPE_MAX`.

| Type  | Bad file                       | Good file                       |
|-------|--------------------------------|---------------------------------|
| `int` | `multiply/bad_int_multiply_01.c` | `multiply/good_int_multiply_01.c` |

**Bad pattern:** `int result = data * 2;` inside `if (data > 0)`.
**Good pattern:** `if (data <= (INT_MAX / 2)) { int result = data * 2; }`.

---

### S03 — Squaring (`data * data`)

A special case of multiplication where both operands are the same variable.

| Type     | Bad file                       | Good file                       |
|----------|--------------------------------|---------------------------------|
| `int64_t`| `square/bad_int64_square_01.c` | `square/good_int64_square_01.c` |
| `short`  | `square/bad_short_square_01.c` | `square/good_short_square_01.c` |

**Bad pattern:** `int64_t result = data * data;` with no `sqrt(INT64_MAX)` guard.
**Good pattern:** `if (llabs(data) <= (long long)sqrt(INT64_MAX)) { ... }`.

---

### S04 — Postfix Increment (`data++`)

The post-increment operator applied to a variable at or near `INT_MAX`.

| Type  | Bad file                      | Good file                      |
|-------|-------------------------------|-------------------------------|
| `int` | `postinc/bad_int_postinc_01.c`| `postinc/good_int_postinc_01.c`|

**Bad pattern:** `data++;` with no `INT_MAX` guard.
**Good pattern:** `if (data < INT_MAX) { data++; }`.

---

### S05 — Prefix Increment (`++data`)

The pre-increment operator. Functionally identical overflow risk to postfix,
but requires a different srcML pattern (`<operator>++</operator>` preceding the operand name).

| Type  | Bad file                     | Good file                     |
|-------|------------------------------|-------------------------------|
| `int` | `preinc/bad_int_preinc_01.c` | `preinc/good_int_preinc_01.c` |

---

## C++ Class Dispatch Variants

All four Juliet flow variants (81–84) demonstrate the same multiplication
overflow in different C++ dispatch contexts. The detector handles all four by
splitting on `<destructor>` as well as `<function>` elements.

### Flow 81 — Virtual method via reference

```cpp
const MultiplyBase& obj = MultiplyBad();
obj.action(data);   // dispatches to overridden action()
```

Files: `cpp_virtual_ref/bad_int_multiply_81.cpp`, `good_int_multiply_81.cpp`

### Flow 82 — Virtual method via pointer

```cpp
MultiplyBase* obj = new MultiplyBad();
obj->action(data);  // dispatches through vtable pointer
delete obj;
```

Files: `cpp_virtual_ptr/bad_int_multiply_82.cpp`, `good_int_multiply_82.cpp`

### Flow 83 — Constructor/destructor on stack

```cpp
MultiplyContainer obj(data);  // stack — destructor runs at scope exit
// arithmetic in ~MultiplyContainer()
```

Files: `cpp_ctor_stack/bad_int_multiply_83.cpp`, `good_int_multiply_83.cpp`

### Flow 84 — Constructor/destructor on heap

```cpp
MultiplyContainer* obj = new MultiplyContainer(data);
delete obj;  // triggers destructor with unchecked multiplication
```

Files: `cpp_ctor_heap/bad_int_multiply_84.cpp`, `good_int_multiply_84.cpp`

---

## Interprocedural Variants (Flow 22)

Two-file flow: data enters in a `_22a` source function, arithmetic is performed
in a `_22b` sink function.

| Scenario      | Source                          | Sink                          |
|---------------|---------------------------------|-------------------------------|
| Multiply bad  | `bad_int_multiply_22a.c`        | `bad_int_multiply_22b.c`      |
| Multiply good | `good_int_multiply_22a.c`       | `good_int_multiply_22b.c`     |
| Add bad       | `bad_int_add_22a.c`             | `bad_int_add_22b.c`           |
| Add good      | `good_int_add_22a.c`            | `good_int_add_22b.c`          |

These require multi-file analysis (see `smell_report_multi.sh`).

---

## Variants Not Covered

| Variant type                     | Reason not covered                                |
|----------------------------------|---------------------------------------------------|
| Bitwise shift overflow           | Different CWE-190 sub-type; separate detector needed |
| Tainted source from `recv()`/`read()` | Requires taint tracking; srcML structural approach only |
| Overflow via type conversion     | CWE-197 (Numeric Truncation) — separate smell      |
| Multi-level class inheritance    | Template/virtual dispatch chains; future work      |
| `__int128` / SIMD types          | Non-standard; srcML may not annotate correctly     |
