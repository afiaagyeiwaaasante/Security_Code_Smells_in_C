#!/bin/bash

mkdir -p results/joern_runtime_per_file

for file in data/juliet/*.c; do
    base=$(basename "$file" .c)
    echo "Processing $base"
    /usr/bin/time -l joern --script <(
        echo "importCpg(\"cpg.bin\");"
        echo "import java.io.PrintWriter;"
        echo "val writer = new PrintWriter(\"results/joern_runtime_per_file/${base}_results.txt\");"
        echo "cpg.call.name(\"gets\").location.map(l => s\"${l.filename}:${l.lineNumber.get}:SCS001:Dangerous_Function_Use:gets\").foreach(writer.println);"
        echo "writer.close();"
    ) 2> results/joern_runtime_per_file/${base}_performance.txt
done