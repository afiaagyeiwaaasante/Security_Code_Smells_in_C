# CWE476 variant coverage

## Sink types (the smell pattern)

| Sink | Description | Covered |
|---|---|---|
| `binary_if` | `&` instead of `&&` in null-check condition | yes |
| `deref_after_check` | pointer checked safely but dereferenced outside check | no |
| `deref_no_check` | pointer dereferenced with no null check at all | no |
| `check_after_deref` | null check appears after the dereference | no |

## Flow variants (how NULL reaches the sink)

The flow variant number in the Juliet filename describes how NULL is
assigned to the pointer before it reaches the sink. The `binary_if`
sink pattern is identical across all flow variants — the detector does
not need to change to handle them.

| Variant range | Flow mechanism |
|---|---|
| 01 | direct assignment in same function |
| 02 | global variable |
| 03–04 | `if(true)` / `if(false)` wrapping |
| 05–06 | `if(static_const)` wrapping |
| 07–10 | `if(rand())` control flow |
| 11–14 | `if(globalTrue)` / `if(globalFalse)` |
| 15–18 | `switch` statement wrapping |
| 21–23 | assignment via separate function call |
| 31–45 | inter-procedural via various patterns |
| 51–54 | multi-file inter-procedural |


| flow variant | wrapper | query change needed | status |
|---|---|---|---|
| 01 | none — baseline | — | tested |
| 02 | if(1){} | none — CONTAINS handles nesting | tested |
| 03 | if(5==5){} | none | tested, passes |
| 05 | if(true){} | none | to test |
| 06 | if(STATIC_CONST){} | none | to test |

| variant range | wrapper type | representative test | status |
|---|---|---|---|
| 01 | none — baseline | bad_binary_if.c | tested |
| 02-04 | if(constant literal) | bad_binary_if_flow02.c | tested |
| 05-06 | if(staticVar) — never reassigned | bad_binary_if_flow05.c | tested |
| 07-10 | if(rand()) — runtime condition | bad_binary_if_flow07.c | to test |
| 11-18 | if(globalVar) | bad_binary_if_flow11.c | tested |
| 21-54 | inter-procedural | bad_interprocedural.c | tested |

## Known gap

Variants 51–54 (multi-file inter-procedural) span multiple `.c` files.
The current pipeline processes one file at a time. Running srcslice
on a srcML archive containing all files would be required to detect
these variants.

## char variant coverage

| variant range | wrapper | representative test | status |
|---|---|---|---|
| 01 | none — baseline | bad_char_01.c | tested |
| 02 | if(1) | bad_char_01.c | tested — CONTAINS handles nesting |
| 03 | if(5==5) | bad_char_01.c | tested — CONTAINS handles nesting |


## char declaration pattern coverage

| pattern | style | query | status |
|---|---|---|---|
| char *data = NULL; data[0] | initializer | $TYPE $PTR = NULL FOLLOWED BY $PTR[$IDX] | tested |
| char *data; data = NULL; data[0] | separate assignment | $PTR = NULL FOLLOWED BY $PTR[$IDX] | tested |
| twoIntsStruct *ptr = NULL; ptr->field | initializer | $TYPE * $PTR = NULL FOLLOWED BY $PTR->$FIELD | tested |
| twoIntsStruct *ptr; ptr = NULL; ptr->field | separate assignment | $PT * $PTR = NULL FOLLOWED BY $PTR->$FIELD | tested |

Both patterns are covered by UNION in detect_null_deref.sh.

All three use the same sink pattern — data[0] with no null guard.
The wrapper depth is irrelevant to detection.
Detector 3 null_deref array index query handles all three.
```

Now update `run_tests.sh` to also cover the `bad_char_01.c` smell and good cases separately since they are three different functions in one file. The current `run_case` function tests the whole file — split into three separate test files for clarity:
```
tests/CWE476/char/
├── bad_char_01.c      — bad_char_null_deref() — expect error [null_deref]
├── smell_char_01.c    — smell_char_no_guard()  — expect warning [missing_guard]
└── good_char_01.c     — good_char_guarded()    — expect clean

## interprocedural severity taxonomy

| finding | source | severity | rule |
|---|---|---|---|
| callee dereferences param, no internal null check | Pass 1 | warning | missingNullCheck |
| caller passes NULL to unsafe callee | Pass 2a | error | nullPointer |
| caller passes unguarded ptr to unsafe callee | Pass 2b | warning | missingNullCheck |
| caller guards before passing (if(ptr!=NULL){callee(ptr)}) | excluded | — | — |

## interprocedural test cases
| file | dereference | expected findings |
|---|---|---|
| bad_interprocedural_01.c | ptr->field | callee smell + caller warning |
| good_interprocedural_01.c | ptr->field | callee smell only |
| bad_char_interprocedural_01.c | ptr[idx] | callee smell + error + warning |

## multi-file variant coverage

| variant | files | pipeline | status |
|---|---|---|---|
| char_22 | 22a.c + 22b.c | smell_report_multi.sh | tested |
| char_51 | 51a.c + 51b.c | smell_report_multi.sh | to test |
| char_52 | 52a+b+c.c | smell_report_multi.sh | to test |
| char_53 | 53a+b+c+d.c | smell_report_multi.sh | to test |
| char_54 | 54a+b+c+d+e.c | smell_report_multi.sh | to test |

## Key finding
srcML can combine multiple source files into one archive.
srcslice tracks data flow across file boundaries in the combined archive.
The interprocedural detector works without modification on the combined XML.
The only infrastructure change is smell_report_multi.sh which accepts
multiple source files and combines them before running the pipeline.