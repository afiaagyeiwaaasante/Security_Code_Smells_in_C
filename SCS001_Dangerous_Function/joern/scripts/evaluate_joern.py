import json

# Paths to your files
ground_truth_file = "results/ground_scs001_truth_filtered.txt"
joern_output_file = "results/joern_scs001_results.txt"
evaluation_file = "results/joern_scs001_evaluation.json"

# Load files as sets for easy comparison
with open(ground_truth_file, "r") as f:
    ground_truth = set(line.strip() for line in f if line.strip())

with open(joern_output_file, "r") as f:
    joern_output = set(line.strip() for line in f if line.strip())

# Compute True Positives, False Positives, False Negatives
tp = joern_output & ground_truth
fp = joern_output - ground_truth
fn = ground_truth - joern_output

# Compute metrics
precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0
f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

# Print evaluation
print("=== Joern SCS001 Evaluation ===")
print(f"True Positives (TP): {len(tp)}")
print(f"False Positives (FP): {len(fp)}")
print(f"False Negatives (FN): {len(fn)}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1_score:.4f}")

# Save detailed evaluation to JSON
evaluation = {
    "TP": list(tp),
    "FP": list(fp),
    "FN": list(fn),
    "precision": precision,
    "recall": recall,
    "f1_score": f1_score
}

with open(evaluation_file, "w") as f:
    json.dump(evaluation, f, indent=4)

print(f"\nDetailed evaluation saved to {evaluation_file}")