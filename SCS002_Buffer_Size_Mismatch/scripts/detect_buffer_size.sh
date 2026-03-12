#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data"
REPORT_DIR="$PROJECT_ROOT/reports"
mkdir -p "$REPORT_DIR"

for file in $(find "$DATA_DIR" -name "*.c"); do
    NAME=$(basename "$file" .c)
    echo "Scanning $file ..."

    # Detect malloc
    srcml "$file" --text="p=malloc(sizeof(int));" -l C++ --srcql 'FIND malloc() CONTAINS src:sizeof' -S -F > "$REPORT_DIR/${NAME}_malloc.xml"
    # Detect calloc
    srcml "$file" --text="p=calloc(1, sizeof(int));" -l C++ --srcql 'FIND calloc() CONTAINS src:sizeof' -S -F > "$REPORT_DIR/${NAME}_calloc.xml"
    # Detect realloc
    srcml "$file" --text="p=realloc(p, sizeof(int));" -l C++ --srcql 'FIND realloc() CONTAINS src:sizeof' -S -F > "$REPORT_DIR/${NAME}_realloc.xml"
done