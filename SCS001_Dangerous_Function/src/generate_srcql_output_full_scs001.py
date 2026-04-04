import os
import subprocess
import re
import json

# === Config ===
JULIET_DIR = "data/juliet"
OUTPUT_FILE = "results/scs001_detected.txt"
JSON_FILE = "results/metrics_scs004.json"
SMELL_ID = "SCS001"
DESCRIPTION = "Dangerous_Function_Use"

# All dangerous functions for SCS001
DANGEROUS_FUNCS = ["gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"]

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)

detections = []
performance = {}

with open(OUTPUT_FILE, "w") as out_file:
    for root, dirs, files in os.walk(JULIET_DIR):
        for file in files:
            if not file.endswith(".c"):
                continue
            file_path = os.path.join(root, file)
            file_runtime = 0.0  # total runtime for all functions in this file

            for func in DANGEROUS_FUNCS:
                # Run srcML + srcQL with --position and -F
                cmd = f'/usr/bin/time -p srcml "{file_path}" --position --srcql "FIND {func}()" -F'
                result = subprocess.run(cmd, shell=True, text=True, capture_output=True)

                # Extract runtime from stderr (real time only)
                runtime_sec = 0.0
                for line in result.stderr.splitlines():
                    if line.startswith("real"):
                        try:
                            runtime_sec = float(line.split()[1])
                        except:
                            runtime_sec = 0.0
                        file_runtime += runtime_sec

                # Parse line numbers from XML stdout
                for line in result.stdout.splitlines():
                    if "pos:start" in line:
                        match = re.search(r'pos:start="(\d+):\d+"', line)
                        if match:
                            line_num = match.group(1)
                            out_file.write(f"{file}:{line_num}:{SMELL_ID}:{DESCRIPTION}:{func}\n")
                            detections.append([file, line_num, SMELL_ID, DESCRIPTION, func])
                            print(f"Detected {func} at line {line_num} in {file} (runtime {runtime_sec:.3f}s)")

            # Save total runtime per file
            performance[file] = round(file_runtime, 3)

# Save JSON with all detections + per-file runtime
json_data = {
    "smell_id": SMELL_ID,
    "smell_name": DESCRIPTION,
    "detections": detections,
    "performance": performance,
    "output_file": OUTPUT_FILE
}

with open(JSON_FILE, "w") as jf:
    json.dump(json_data, jf, indent=4)

print(f"\nsrcQL output saved to {OUTPUT_FILE}")
print(f"JSON evaluation file saved to {JSON_FILE}")