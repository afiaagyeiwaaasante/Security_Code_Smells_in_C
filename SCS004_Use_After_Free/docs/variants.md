# CWE-416 variant coverage

## Sink types

Each sink type is a distinct structural smell pattern. One detector covers each.

| Sink | Description | Detector | Severity | Status |
|---|---|---|---|---|
| `use_after_free` | `free(ptr)` then `*ptr`, `ptr->field`, or `ptr[idx]` in same function | 1 | error | covered (function-arg pattern) |
| `double_free` | `free(ptr)` called twice on same pointer without reassignment | 2 | error | planned |
| `interprocedural_uaf` | pointer freed in callee; caller uses pointer after the call | 3 | error / warning | covered |

---

## Flow variants

The flow variant number in Juliet filenames describes how the flaw is
wrapped in the function. The inner smell pattern is identical across all
variants — the structural query (`CONTAINS`, `FOLLOWED BY`) handles
arbitrary nesting depth without query changes.

| Variant | Outer wrapper | Status |
|---|---|---|
| 01 | none — baseline | planned |
| 02 | `if(1)` — literal true | planned |
| 03 | `if(5==5)` — constant expression | planned |
| 04 | `if(STATIC_CONST_TRUE)` — static const macro | planned |
| 05–06 | `if(staticTrue)` / `if(staticFalse)` — static variable | planned |
| 07–08 | `if(staticFive==5)` / `if(staticReturnsTrue())` | planned |
| 09–14 | `if(globalTrue/False/Func())` — global variable or function | planned |
| 15 | `switch(6) case 6:` | planned |
| 16 | `while(1) { ... break; }` | planned |
| 17 | `for(j=0; j<1; j++)` | planned |
| 18 | `goto sink:` | planned |

---

## use_after_free — Detector 1

### Data type coverage

The query `FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)` is
type-agnostic — it matches the structural pattern regardless of the pointer type.

| Type | Minimal bad file | Minimal good file | Status |
|---|---|---|---|
| `char *` | `char/bad_use_after_free_char_01.c` | `char/good_use_after_free_char_01.c` | tested |
| `int *` | `int/bad_use_after_free_int_01.c` | `int/good_use_after_free_int_01.c` | tested |
| `int64_t *` | `int64/bad_use_after_free_int64_01.c` | `int64/good_use_after_free_int64_01.c` | tested |
| `long *` | `long/bad_use_after_free_long_01.c` | `long/good_use_after_free_long_01.c` | tested |
| `struct *` | — | — | not tested |
| `wchar_t *` | — | — | not tested |

---

## double_free — Detector 2

### Minimal test cases (to be created)

| File | Pattern | Status |
|---|---|---|
| `char/bad_double_free_01.c` | `free(data); free(data)` | not created |
| `char/good_double_free_01.c` | single free | not created |

---

## interprocedural_uaf — Detector 3

### Severity taxonomy

| Finding | Source | Severity | Rule |
|---|---|---|---|
| Callee frees parameter | Pass 1 | warning | useAfterFree |
| Caller uses pointer after unsafe callee call | Pass 2 | error | useAfterFree |
| Caller guards before using (`ptr = callee_that_returns_ptr()`) | excluded | — | — |

### Multi-file test cases

| Variant | Files | Status |
|---|---|---|
| long_22 | `interprocedural/bad_interprocedural_uaf_long_22a.c` + `22b.c` | tested |
| char_22 | `interprocedural/bad_interprocedural_uaf_char_22a.c` + `22b.c` | not created |
| int_22 | `interprocedural/bad_interprocedural_uaf_int_22a.c` + `22b.c` | not created |

---

## freed_pointer variants

The `freed_pointer/` directory contains Juliet cases where the flaw is
a function returning a freed pointer to its caller. These require
interprocedural tracking and are tracked separately.

| File | Pattern | Status |
|---|---|---|
| `freed_pointer/CWE416_Use_After_Free__return_freed_ptr_01.c` | baseline | not tested |
