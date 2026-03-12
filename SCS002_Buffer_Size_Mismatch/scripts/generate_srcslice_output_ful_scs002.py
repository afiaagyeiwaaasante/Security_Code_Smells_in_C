import os
import subprocess
import re
import json

# === Config ===
JULIET_DIR = "data/juliet/s01"
OUTPUT_FILE = "results/scs002_detected3.txt"
JSON_FILE = "results/metrics_scs003.json"

SMELL_ID = "SCS002"
DESCRIPTION = "Buffer_Size_Mismatch"

MEMORY_FUNCS = ["malloc", "calloc", "realloc"]

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)

detections = []
performance = {}

# Extract variable used in size expression
def extract_size_variable(expression):

    # Example patterns:
    # data * sizeof(int)
    # sizeof(int) * data
    # data*sizeof(int)

    match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*sizeof', expression)
    if match:
        return match.group(1)

    match = re.search(r'sizeof\s*\([^)]*\)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)', expression)
    if match:
        return match.group(1)

    return "unknown"


with open(OUTPUT_FILE, "w") as out_file:

    for root, dirs, files in os.walk(JULIET_DIR):

        for file in files:

            if not file.endswith(".c"):
                continue

            file_path = os.path.join(root, file)
            file_runtime = 0.0

            for func in MEMORY_FUNCS:

                cmd = f'/usr/bin/time -p srcml "{file_path}" --position --srcql "FIND {func}($ARG)" -F'

                result = subprocess.run(
                    cmd,
                    shell=True,
                    text=True,
                    capture_output=True
                )

                # Extract runtime
                runtime_sec = 0.0
                for line in result.stderr.splitlines():
                    if line.startswith("real"):
                        try:
                            runtime_sec = float(line.split()[1])
                        except:
                            runtime_sec = 0.0

                        file_runtime += runtime_sec

                # Parse XML output
                lines = result.stdout.splitlines()

                for i, line in enumerate(lines):

                    if "pos:start" not in line:
                        continue

                    match = re.search(r'pos:start="(\d+):\d+"', line)

                    if not match:
                        continue

                    line_num = match.group(1)

                    # Try to capture the argument expression
                    expr = ""

                    for j in range(i, min(i+10, len(lines))):
                        if "<argument>" in lines[j]:
                            expr = lines[j]
                            break

                    size_var = extract_size_variable(expr)

                    out_file.write(
                        f"{file}:{line_num}:{SMELL_ID}:{DESCRIPTION}:{func}:{size_var}\n"
                    )

                    detections.append(
                        [file, line_num, SMELL_ID, DESCRIPTION, func, size_var]
                    )

                    print(
                        f"Detected {func} at line {line_num} in {file} "
                        f"(size variable: {size_var}, runtime {runtime_sec:.3f}s)"
                    )

            performance[file] = round(file_runtime, 3)

# Save JSON
json_data = {
    "smell_id": SMELL_ID,
    "smell_name": DESCRIPTION,
    "detections": detections,
    "performance": performance,
    "output_file": OUTPUT_FILE
}

with open(JSON_FILE, "w") as jf:
    json.dump(json_data, jf, indent=4)

print("\nsrcQL output saved to", OUTPUT_FILE)
print("JSON evaluation file saved to", JSON_FILE)