#!/bin/bash

find data/juliet -type f -name "*.c" | while read FILE; do

    BASENAME=$(basename "$FILE" .c)
    XML_FILE="results/${BASENAME}.xml"
    SLICE_FILE="results/${BASENAME}_slice.json"

    echo "Processing $FILE"

    /usr/bin/time -f srcml "$FILE, %E, %M" \
        -o "$XML_FILE" --position --hash \
        2>> results/performance_log.txt

    /usr/bin/time -f ./srcslice -i "$XML_FILE, %E, %M" \
        -o "$SLICE_FILE" \
        2>> results/performance_log.txt

done