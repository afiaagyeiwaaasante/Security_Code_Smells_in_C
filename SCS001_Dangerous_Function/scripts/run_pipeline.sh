find data/juliet -type f -name "*.c" | while read FILE; do

    BASENAME=$(basename "$FILE" .c)
    XML_FILE="results/${BASENAME}.xml"
    SLICE_FILE="results/${BASENAME}_slice.json"

    echo "Processing $FILE"

    /usr/bin/time \
        srcml "$FILE" --position --hash\
        -o "$XML_FILE" \
        2>> results/xml_performance_log.txt

(
    cd ../../ # move to the Security-Code-Smells folder
    /usr/bin/time ./tools/build/bin/srcslice -i "SCS001_Dangerous_Function/${XML_FILE}" \
        -o "SCS001_Dangerous_Function/${SLICE_FILE}" \
        2>> SCS001_Dangerous_Function/results/slice_performance_log.txt
)
    

done