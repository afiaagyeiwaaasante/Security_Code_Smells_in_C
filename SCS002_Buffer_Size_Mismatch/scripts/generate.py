import os
import subprocess
import re
import json

# === Config ===
JULIET_DIR = "data/juliet"
OUTPUT_FILE = "results/scs002_detected.txt"

# All memory allocation functions for SCS002
MEMORY_FUNCS = ["malloc", "calloc", "realloc"]

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)


with open(OUTPUT_FILE, "w") as out_file:
    for root, dirs, files in os.walk(JULIET_DIR):
        for file in files:
            if not file.endswith(".c"):
                continue
            file_path = os.path.join(root, file)
            file_runtime = 0.0  # total runtime for all functions in this file

            for func in MEMORY_FUNCS:
                # Run srcML + srcQL with --position and -F
                cmd = f'/usr/bin/time -p srcml "{file_path}" --position --srcql "FIND {func}()" -F'
                result = subprocess.run(cmd, shell=True, text=True, capture_output=True)

                
                

