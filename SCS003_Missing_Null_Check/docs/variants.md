# CWE-476 variant coverage

## Sink types

Each sink type is a distinct structural smell pattern. One detector covers each.

| Sink | Description | Detector | Severity | Status |
|---|---|---|---|---|
| `binary_if` | `&` instead of `&&` in null-check condition | 1 | error | covered |
| `interprocedural` | NULL passed to callee that dereferences without guard | 2 | error / warning | covered |
| `null_deref` | `ptr = NULL` then `ptr->field` or `ptr[idx]`, no guard | 3 | error | covered |
| `missing_guard` | unguarded `->` or `[]` dereference, no null check in function | 4 | warning | covered |
| `deref_after_check` | `if(ptr == NULL) { *ptr }` — deref inside null-confirmed branch | 5 | error | covered |
| `check_after_deref` | `*ptr` then `if(ptr != NULL)` — guard placed after dereference | 6 | warning | covered |

---

## Flow variants

The flow variant number in Juliet filenames describes how the flaw is
wrapped in the function. The inner smell pattern is identical across all
variants — the structural query (`CONTAINS`, `FOLLOWED BY`) handles
arbitrary nesting depth without query changes.

| Variant | Outer wrapper | Representative test | Status |
|---|---|---|---|
| 01 | none — baseline | `bad_binary_if_01.c` | tested |
| 02 | `if(1)` — literal true | `bad_binary_if_flow02.c` | tested |
| 03 | `if(5==5)` — constant expression | — | passes (same as 02) |
| 04 | `if(STATIC_CONST_TRUE)` — static const macro | — | passes (same as 02) |
| 05–06 | `if(staticTrue)` / `if(staticFalse)` — static variable | `bad_binary_if_flow05.c` | tested |
| 07–08 | `if(staticFive==5)` / `if(staticReturnsTrue())` | — | passes (CONTAINS depth-agnostic) |
| 09–14 | `if(globalTrue/False/Func())` — global variable or function | `bad_binary_if_flow11.c` | tested |
| 15 | `switch(6) case 6:` | — | passes |
| 16 | `while(1) { ... break; }` | — | passes |
| 17 | `for(j=0; j<1; j++)` | — | passes |
| 18 | `goto sink:` | — | passes |

---

## binary_if — Detector 1

| Representative file | Wrapper | Status |
|---|---|---|
| `binary_if/bad_binary_if_01.c` | none | tested |
| `binary_if/bad_binary_if_flow02.c` | `if(1)` | tested |
| `binary_if/bad_binary_if_flow05.c` | `if(staticTrue)` — two bad functions | tested |
| `binary_if/bad_binary_if_flow11.c` | `if(globalReturnsTrueOrFalse())` — mixed `&` and `&&` in same function | tested |
| `binary_if/good_binary_if_01.c` | — | clean (no false positive) |

---

## interprocedural — Detector 2

### Severity taxonomy

| Finding | Source | Severity | Rule |
|---|---|---|---|
| Callee dereferences param with no internal null check | Pass 1 | warning | missingNullCheck |
| Caller passes NULL to unsafe callee | Pass 2a | error | nullPointer |
| Caller passes unguarded ptr to unsafe callee | Pass 2b | warning | missingNullCheck |
| Caller guards before passing (`if(ptr!=NULL){callee(ptr)}`) | excluded | — | — |

### Single-file test cases

| File | Dereference | Expected findings |
|---|---|---|
| `interprocedural/bad_interprocedural_01.c` | `ptr->field` | callee smell + caller warning |
| `interprocedural/good_interprocedural_01.c` | `ptr->field` | callee smell only |
| `interprocedural/bad_char_interprocedural_01.c` | `ptr[idx]` | callee smell + error + warning |

### Multi-file test cases

| Variant | Files | Pipeline | Status |
|---|---|---|---|
| char_22 | `bad_char_interprocedural_22a.c` + `22b.c` | `smell_report_multi.sh` | tested |
| char_51–54 | 3–5 file chains | `smell_report_multi.sh` | not tested |

---

## null_deref — Detector 3

### Declaration pattern coverage

| Pattern | Style | Status |
|---|---|---|
| `twoIntsStruct *ptr = NULL; ptr->field` | initializer + `->` | tested |
| `twoIntsStruct *ptr; ptr = NULL; ptr->field` | separate assignment + `->` | tested |
| `char *data = NULL; data[0]` | initializer + `[]` | tested |
| `char *data; data = NULL; data[0]` | separate assignment + `[]` | tested |

Both patterns in each group are covered by `UNION` in `detect_null_deref.sh`.

### Test cases

| File | Pattern | Status |
|---|---|---|
| `deref_no_check/bad_null_deref_01.c` | `->` struct member | tested |
| `deref_no_check/good_guarded_01.c` | guarded `->` | clean (no false positive) |
| `char/bad_char_01.c` | `[]` initializer style | tested |
| `char/bad_char_01b.c` | `[]` assignment style | tested |
| `char/good_char_01.c` | guarded `[]` | clean (no false positive) |

---

## missing_guard — Detector 4

### Test cases

| File | Pattern | Status |
|---|---|---|
| `deref_no_check/smell_no_guard_01.c` | `ptr=&local` then `ptr->field`, no guard | tested |
| `char/smell_char_01b.c` | `data=NULL` then `data[0]`, no guard | tested |
| `char/smell_char_01.c` | `char *data = "Good"` then `data[0]` | **false negative** — string literal init not matched |

---

## deref_after_check — Detector 5

| File | Pattern | Status |
|---|---|---|
| `after_check/bad_deref_after_check_01.c` | `if(ptr == NULL) { *ptr }` — baseline | tested |

Flow variants 01–18 from Juliet (`deref_after_check_01.c` – `18.c`) all share
the same inner `if(ptr == NULL) { *ptr }` pattern. The outer wrapper is
irrelevant — `CONTAINS` is depth-agnostic. The Juliet originals remain in the
folder as reference; only the minimal case is actively tested.

---

## check_after_deref — Detector 6

| File | Pattern | Status |
|---|---|---|
| `check_after_deref/bad_check_after_deref_01.c` | `*ptr` then `if(ptr != NULL)` — baseline | tested |

Flow variants 01–18 from Juliet (`null_check_after_deref_01.c` – `18.c`) all
share the same core pattern. The outer wrapper is irrelevant. The Juliet
originals remain in the folder as reference.

---

## NULL propagation coverage (struct variants)

| Juliet variant | Propagation mechanism | Detected | Severity | Notes |
|---|---|---|---|---|
| 01–18 | Direct: `data = NULL; data->field` | yes | error | `null_deref` |
| 21 | Via static flag + function call | yes | error / warning | `interprocedural` |
| 22a/b | Via global + function call (multi-file) | yes | error / warning | `interprocedural` multi-file |
| 31 | Via local copy: `dataCopy = data` | partial | warning only | `missing_guard` fires; `null_deref` misses |
| 32 | Via pointer-to-pointer: `*dataPtr = NULL` | no | — | complete false negative |
| 34 | Via union aliasing | partial | warning only | `missing_guard` fires; `null_deref` misses |
| 41–45 | Via function / function pointer | yes | error / warning | `interprocedural` |
| 51–68 | Multi-file argument chains | partial | — | not fully tested |
