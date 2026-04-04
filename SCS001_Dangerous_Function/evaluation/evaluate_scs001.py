import os

# === Config ===
GROUND_TRUTH_FILE = "results/ground_scs001_truth_filtered.txt"   # your file with correct SCS001 detections
SRCQL_OUTPUT_FILE = "results/scs001_detected.txt"

# === Read files into sets for comparison ===
with open(GROUND_TRUTH_FILE, "r") as f:
    ground_truth = set(line.strip() for line in f if line.strip())

with open(SRCQL_OUTPUT_FILE, "r") as f:
    srcql_output = set(line.strip() for line in f if line.strip())

# === Compute True Positives (TP), False Positives (FP), False Negatives (FN) ===
TP = ground_truth & srcql_output
FP = srcql_output - ground_truth
FN = ground_truth - srcql_output

num_TP = len(TP)
num_FP = len(FP)
num_FN = len(FN)

# === Compute Precision, Recall, F1-score ===
precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

# === Print Results ===
print(f"=== SCS001 Evaluation ===")
print(f"True Positives (TP): {num_TP}")
print(f"False Positives (FP): {num_FP}")
print(f"False Negatives (FN): {num_FN}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1_score:.4f}")

# Optional: Save detailed results
import json
results = {
    "TP_count": num_TP,
    "FP_count": num_FP,
    "FN_count": num_FN,
    "Precision": round(precision, 4),
    "Recall": round(recall, 4),
    "F1_score": round(f1_score, 4),
    "TP": list(TP),
    "FP": list(FP),
    "FN": list(FN)
}

os.makedirs("results", exist_ok=True)
with open("results/scs001_evaluation.json", "w") as jf:
    json.dump(results, jf, indent=4)

print("\nDetailed evaluation saved to results/scs001_evaluation.json")