input_file = "results/ground_scs001_truth.txt"
output_file = "results/ground_scs001_truth_filtered.txt"

with open(input_file) as f:
    lines = f.readlines()

filtered = []

for line in lines:
    parts = line.strip().split(":")
    line_number = int(parts[1])

    # Remove comment detections (line 11)
    if line_number != 11:
        filtered.append(line)

with open(output_file, "w") as f:
    f.writelines(filtered)

print("Filtered ground truth saved to:", output_file)