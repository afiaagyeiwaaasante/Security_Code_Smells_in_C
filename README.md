# Security Code Smells in C — Detection & Analysis
> Master's Thesis Research Repository  
> Tools: srcML · srcSlice · srcQL · Python · Juliet Test Suite

---

## Overview

This repository contains the full research pipeline for **detecting and analyzing security code smells in C source code**. It uses program slicing (srcSlice) and structural XML querying (srcQL/XPath) to identify, locate, and annotate security vulnerabilities based on the **NIST Juliet Test Suite**.

Each security code smell (SCS) is treated as an independent, self-contained study under its own folder.

---

## Repository Structure

```
Security-Code-Smells/
│
├── README.md                        ← this file
├── METHODOLOGY.md                   ← overall research methodology
├── requirements.txt                 ← Python dependencies
├── tools/                           ← srcML, srcSlice, srcAttributor builds
│   ├── srcML/
│   ├── srcML_srcslice/
│   ├── srcAttributor/
│   └── srcSlice/
│
└── SCS003_Missing_Null_Check/       ← Security Code Smell #003
    ├── README.md                    ← smell-specific documentation
    ├── DETECTION_RULE.md            ← formal detection rule definition
    │
    ├── testsuites/                  ← Juliet Test Suite C files
    │   ├── binary_if/
    │   │   ├── CWE476_NULL_Pointer_Dereference__binary_if_01.c
    │   │   └── ...
    │   ├── char/
    │   └── ...
    │
    ├── data/                        ← generated analysis files
    │   ├── XMLFile/                 ← srcML XML output
    │   ├── SliceFile/               ← srcSlice JSON output
    │   └── AttributeFile/           ← annotated XML output
    │
    ├── results/                     ← sink element XML files
    │   └── binary_if/
    │
    ├── reports/                     ← JSON detection reports
    │   └── SCS003_Missing_Null_Check/
    │
    └── src/                         ← detection pipeline scripts
        ├── pipeline.py              ← main entry point (runs all steps)
        ├── step1_detect.py          ← Step 1: JSON rule detection
        ├── step2_locate.py          ← Step 2: XPath sink location
        ├── step3_annotate.py        ← Step 3: XML annotation
        └── utils.py                 ← shared helpers
```

---

## Security Code Smells Catalogue

| ID | Name | CWE | Status |
|----|------|-----|--------|
| SCS003 | Missing Null Check | CWE-476 | ✅ In Progress |
| SCS001 | Buffer Overflow | CWE-121 | 🔲 Planned |
| SCS002 | Use After Free | CWE-416 | 🔲 Planned |
| SCS004 | Integer Overflow | CWE-190 | 🔲 Planned |
| SCS005 | Format String | CWE-134 | 🔲 Planned |

---

## Pipeline Overview

```
C Source File (Juliet Test Suite)
        │
        ▼
[1] srcml --position --hash
        │
        ▼
   XMLFile/*.xml          ← structured XML representation
        │
        ▼
[2] srcslice
        │
        ▼
   SliceFile/*.json        ← data flow / slice profiles
        │
        ▼
[3] src/step1_detect.py   ← apply detection rules to JSON
        │
        ▼
[4] src/step2_locate.py   ← locate sink with XPath on XML
        │
        ▼
[5] src/step3_annotate.py ← annotate XML with sec:smell attribute
        │
        ▼
   AttributeFile/*.xml     ← annotated output
   results/*.xml           ← extracted sink elements
   reports/*.json          ← detection report
```

---

## Quick Start

### 1. Install dependencies
```bash
pip3 install lxml --break-system-packages
```

### 2. Convert C file to srcML XML
```bash
srcml --position --hash \
    testsuites/binary_if/CWE476_NULL_Pointer_Dereference__binary_if_01.c \
    -o data/XMLFile/CWE476_binary_if_01.xml
```

### 3. Run srcSlice
```bash
srcslice data/XMLFile/CWE476_binary_if_01.xml \
    -o data/SliceFile/CWE476_binary_if_01.json
```

### 4. Run full detection pipeline
```bash
cd src/
python3 pipeline.py \
    ../data/SliceFile/CWE476_binary_if_01.json \
    ../data/XMLFile/CWE476_binary_if_01.xml \
    ../data/AttributeFile/CWE476_binary_if_01_annotated.xml
```

---

## Reproducibility

All test cases are from the **NIST Juliet Test Suite for C/C++**:  
https://samate.nist.gov/SARD/test-suites/116

Tool versions used:
- srcML: branch `srcql_srcslice`
- srcSlice: branch `develop`
- Python: 3.x
- lxml: 5.x

---

## Thesis Export (Overleaf)

See `METHODOLOGY.md` for the LaTeX-ready description of the pipeline, detection rules, and results tables formatted for direct use in Overleaf.