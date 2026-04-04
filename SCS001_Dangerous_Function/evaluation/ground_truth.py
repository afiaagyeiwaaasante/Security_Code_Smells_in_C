import os
import re

# === Config ===
JULIET_DIR = "data/juliet"  # folder with Juliet C files
OUTPUT_FILE = "results/ground_scs001_truth.txt"
SMELL_ID = "SCS001"
DESCRIPTION = "Dangerous_Function_Use"

# Dangerous functions for SCS001
DANGEROUS_FUNCS = ["gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"]

# Make sure output folder exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, "w") as out_file:
    # Walk through Juliet C files
    for root, dirs, files in os.walk(JULIET_DIR):
        for file in files:
            if not file.endswith(".c"):
                continue
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    line_strip = line.strip()
                    # Only look at lines containing known dangerous functions
                    for func in DANGEROUS_FUNCS:
                        # match function call (e.g., gets(data);)
                        if re.search(r'\b{}\b\s*\('.format(func), line_strip):
                            # Write to ground truth
                            out_file.write(f"{file}:{line_num}:{SMELL_ID}:{DESCRIPTION}:{func}\n")
                            break  # avoid duplicate detection per line
print(f"Ground truth file generated: {OUTPUT_FILE}")