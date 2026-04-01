# SCS003 — Missing Null Check (CWE-476)

## Description

A **Missing Null Check** occurs when a pointer variable is dereferenced without first verifying that it is not `NULL`. This is classified as **CWE-476: NULL Pointer Dereference** and can lead to program crashes, denial of service, or exploitable memory corruption.

---

## Test Suite Scenarios

The Juliet Test Suite provides multiple flow variants for CWE-476:

| Scenario               | Description                  | Status         |
|:-----------------------|:-----------------------------|:---------------|
| `binary_if`            | Single `&` in if condition   | ✅ Implemented |
| `char`                 | Null pointer via char type   | 🔲 Planned   |
| `int`                  | Null pointer via int type    | 🔲 Planned   |
| `long`                 | Null pointer via long type   | 🔲 Planned   |
| `struct`               | Null pointer via struct type | 🔲 Planned   |
| `twointsstructpointer` | Null via struct pointer      | 🔲 Planned   |
| 'deref_after_check'    | Dereference after check      | 🔲 Planned   |
| 'deref_no_check'       | Dereference with no check    | 🔲 Planned   |


## Security Smell Pattern

Detects the `binary_if` variant of CWE-476 where a bitwise AND (`&`) is used instead of logical AND (`&&`) in a null-check condition, causing unconditional pointer dereference.

## What it detects
```c
// BAD — & does not short-circuit, ptr->intOne always evaluated
if ((ptr != NULL) & (ptr->intOne == 5))

// GOOD — && short-circuits, safe
if ((ptr != NULL) && (ptr->intOne == 5))
```


---

## Detection Rule

| Rule | Check | Description |
|------|-------|-------------|
| Rule 1 | `type contains "*"` | Variable is a pointer |
| Rule 2 | `dependence == []` | No null check dependency |
| Rule 3 | `use line exists` | Pointer is actually used |
| Rule 4 | `function contains known sink` | In a vulnerable function context |

### XPath Sink Confirmation

| Check | XPath | Description |
|-------|-------|-------------|
| Check 1 | `//src:if_stmt[@pos:start[starts-with(.,'LINE:')]]` | if_stmt at use line |
| Check 2 | `//src:if_stmt//src:operator[.='&']` | Bitwise & operator |
| Check 3 | `//src:if_stmt//src:operator[.='->']` | Pointer dereference |


---

## Folder Structure

```
SCS003_Missing_Null_Check/
│
├── README.md                    ← this file
├── DETECTION_RULE.md            ← formal detection rule
│
├── testsuites/                  ← Juliet C test files
│   ├── binary_if/
│   ├── char/
│   └── ...
│
├── data/
│   ├── XMLFile/                 ← srcML XML files
│   ├── SliceFile/               ← srcSlice JSON files
│   └── AttributeFile/           ← annotated XML files
│
├── results/                     ← extracted sink elements
│   └── binary_if/
│
├── reports/                     ← JSON detection reports
│   └── SCS003_Missing_Null_Check/
│
└── src/                         ← detection scripts
    ├── pipeline.py
    ├── step1_detect.py
    ├── step2_locate.py
    ├── step3_annotate.py
    └── utils.py
```

---

## Running the Pipeline

```bash
# Step 1: Convert C to XML
srcml --position --hash testsuites/binary_if/<file>.c \
    -o data/XMLFile/<file>.xml

# Step 2: Run srcSlice
srcslice data/XMLFile/<file>.xml \
    -o data/SliceFile/<file>.json

# Step 3: Run full detection pipeline
cd src/
python3 pipeline.py \
    ../data/SliceFile/<file>.json \
    ../data/XMLFile/<file>.xml \
    ../data/AttributeFile/<file>_annotated.xml
```

---

## Output Files

| File | Location | Description |
|------|----------|-------------|
| `*_annotated.xml` | `data/AttributeFile/` | Full XML with `sec:smell` attribute |
| `*_sink_element.xml` | `results/` | Extracted sink `if_stmt` element |
| `*_sink_report.json` | `reports/SCS003_Missing_Null_Check/` | JSON detection report |
| `*_findings.json` | `data/SliceFile/` | Intermediate findings from Step 1 |