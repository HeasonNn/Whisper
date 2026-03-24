#!/usr/bin/env python3
"""Extract Whisper results and compute packet-level AUC/F1 metrics.
   Follows eTRACE/scripts/extract_results.py design with attack_groups.py.
"""
import argparse
import csv
import json
import random
from pathlib import Path
from statistics import mean, stdev
from typing import Optional
from dataclasses import dataclass

from attack_groups import match_group

NUMERIC_METRICS = ("auc", "f1", "precision", "recall")
RAW_COLUMNS = (
    "algorithm", "dataset", "file", "attack_category",
    "auc", "f1", "precision", "recall",
    "total_packets", "malicious_packets", "total_flows", 
    "result_path", "status",
)

@dataclass
class ResultRecord:
    algorithm: str
    dataset: str
    file: str
    attack_category: Optional[str]
    auc: Optional[float]
    f1: float
    precision: float
    recall: float
    total_packets: int
    malicious_packets: int
    total_flows: int
    result_path: str
    status: str


def compute_auc_roc_fast(scores, labels, max_samples=100000):
    """Compute AUC-ROC with sampling for large datasets."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    
    if len(scores) > max_samples:
        indices = random.sample(range(len(scores)), max_samples)
        scores = [scores[i] for i in indices]
        labels = [labels[i] for i in indices]
        n_pos = sum(labels)
        n_neg = len(labels) - n_pos
    
    paired = sorted(zip(scores, labels), key=lambda x: -x[0])
    tp = fp = 0
    auc = 0.0
    prev_fp_rate = prev_tp_rate = 0.0
    for score, label in paired:
        if label: tp += 1
        else: fp += 1
        fp_rate = fp / n_neg
        tp_rate = tp / n_pos
        auc += (fp_rate - prev_fp_rate) * (tp_rate + prev_tp_rate) / 2
        prev_fp_rate, prev_tp_rate = fp_rate, tp_rate
    return auc


def compute_metrics_at_threshold(scores, labels, threshold):
    tp = sum(1 for s, l in zip(scores, labels) if s > threshold and l)
    fp = sum(1 for s, l in zip(scores, labels) if s > threshold and not l)
    fn = sum(1 for s, l in zip(scores, labels) if s <= threshold and l)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return f1, precision, recall


def find_best_f1(scores, labels, max_samples=10000):
    if len(scores) > max_samples:
        indices = random.sample(range(len(scores)), max_samples)
        scores = [scores[i] for i in indices]
        labels = [labels[i] for i in indices]
    
    thresholds = sorted(set(scores))
    best = (0.0, 0.0, 0.0, 0.0)
    for thresh in thresholds:
        f1, p, r = compute_metrics_at_threshold(scores, labels, thresh)
        if f1 > best[0]: best = (f1, thresh, p, r)
    for thresh in [30, 40, 50, 60, 70, 80, 100, 150, 200]:
        f1, p, r = compute_metrics_at_threshold(scores, labels, thresh)
        if f1 > best[0]: best = (f1, thresh, p, r)
    return best


def parse_result_file(result_path, label_path, algorithm="whisper"):
    try:
        with open(result_path, "r") as f: data = json.load(f)
    except: return None
    results = data.get("Results", [])
    if not results: return None
    try:
        with open(label_path, "r") as f: label_str = f.read().strip()
        labels = [1 if c == "1" else 0 for c in label_str]
    except: return None
    
    parts = result_path.parts
    dataset = parts[-2] if len(parts) >= 2 else "unknown"
    file_name = result_path.stem
    
    # Use match_group from attack_groups.py
    attack_category = match_group(dataset, file_name)
    
    packet_scores, packet_labels = [], []
    total_flows = 0
    for entry in results:
        if len(entry) < 5: continue
        addr, distance, cluster, is_mal, pkt_indices = entry[:5]
        total_flows += 1
        for idx in pkt_indices:
            if idx < len(labels):
                packet_scores.append(distance)
                packet_labels.append(labels[idx])
    
    if not packet_scores: return None
    
    n_pos = sum(packet_labels)
    n_neg = len(packet_labels) - n_pos
    auc = compute_auc_roc_fast(packet_scores, packet_labels)
    best_f1, best_thresh, best_p, best_r = find_best_f1(packet_scores, packet_labels)
    
    if n_pos == 0: status = "no_positive"
    elif n_neg == 0: status = "no_negative"
    elif auc is None: status = "auc_undefined"
    else: status = "ok"
    
    return ResultRecord(
        algorithm=algorithm, dataset=dataset, file=file_name,
        attack_category=attack_category,
        auc=auc, f1=best_f1, precision=best_p, recall=best_r,
        total_packets=len(packet_labels), malicious_packets=n_pos,
        total_flows=total_flows, result_path=str(result_path), status=status
    )


class ResultAggregator:
    def __init__(self, records): self.records = list(records)
    
    def to_raw_rows(self): 
        return [{c: getattr(r, c) for c in RAW_COLUMNS} for r in self.records]
    
    def group_stats(self, group_keys):
        grouped = {}
        for r in self.records:
            key = tuple(getattr(r, f) for f in group_keys)
            grouped.setdefault(key, []).append(r)
        rows = []
        for key, items in grouped.items():
            row = dict(zip(group_keys, key))
            row["count"] = len(items)
            row["total_packets"] = sum(r.total_packets for r in items)
            row["malicious_packets"] = sum(r.malicious_packets for r in items)
            row["total_flows"] = sum(r.total_flows for r in items)
            valid_records = [r for r in items if r.auc is not None]
            for m in NUMERIC_METRICS:
                if m == "auc": vals = [getattr(r, m) for r in valid_records]
                else: vals = [getattr(r, m) for r in items]
                row[f"{m}_mean"] = mean(vals) if vals else None
                row[f"{m}_std"] = stdev(vals) if len(vals) > 1 else (0.0 if vals else None)
            row["valid_auc_count"] = len(valid_records)
            rows.append(row)
        return sorted(rows, key=lambda x: tuple(str(x.get(k, "")) for k in group_keys))


def build_group_columns(group_keys):
    cols = list(group_keys) + ["count", "total_packets", "malicious_packets", "total_flows", "valid_auc_count"]
    for m in NUMERIC_METRICS: cols.extend([f"{m}_mean", f"{m}_std"])
    return cols


def write_csv(path, rows, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(columns))
        w.writeheader()
        for r in rows: w.writerow({c: r.get(c) for c in columns})


def filter_attack_category_records(records):
    return [r for r in records if r.attack_category is not None]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="results")
    parser.add_argument("--output-dir", default="results/_summary")
    parser.add_argument("--data-dir", default="/home/hs/data")
    parser.add_argument("--algorithm", default="whisper")
    args = parser.parse_args()
    
    random.seed(42)
    
    input_dir = Path(args.input_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    data_dir = Path(args.data_dir).resolve()
    
    dataset_map = {
        "cic_apt_iot": "CIC_APT_IIoT2024", 
        "ciciot2025": "CICIIOT2025", 
        "dohbrw": "DoHBrw", 
        "hypervision": "hypervision", 
        "ids2017": "CICIDS2017", 
        "unsw": "UNSW_NB15"
    }
    
    if not input_dir.is_dir(): raise SystemExit(f"Not found: {input_dir}")
    
    files = sorted(input_dir.rglob("*.json"))
    records = []
    status_counts = {}
    
    for fp in files:
        if "_summary" in str(fp): continue
        parts = fp.parts
        dataset = parts[-2] if len(parts) >= 2 else "unknown"
        file_name = fp.stem
        data_dataset = dataset_map.get(dataset, dataset)
        label_path = data_dir / data_dataset / f"{file_name}.label"
        if not label_path.exists(): continue
        r = parse_result_file(fp, label_path, args.algorithm)
        if r:
            records.append(r)
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
    
    if not records: raise SystemExit("No records")
    print(f"Parsed {len(records)} files:")
    for s, c in sorted(status_counts.items()): print(f"  - {s}: {c}")
    
    agg = ResultAggregator(records)
    cat_records = filter_attack_category_records(records)
    cat_agg = ResultAggregator(cat_records)
    
    write_csv(output_dir / "results_raw.csv", agg.to_raw_rows(), RAW_COLUMNS)
    write_csv(output_dir / "results_by_algorithm.csv", agg.group_stats(["algorithm"]), build_group_columns(["algorithm"]))
    write_csv(output_dir / "results_by_dataset.csv", agg.group_stats(["dataset"]), build_group_columns(["dataset"]))
    write_csv(output_dir / "results_by_file.csv", agg.group_stats(["dataset", "file"]), build_group_columns(["dataset", "file"]))
    write_csv(output_dir / "results_by_attack_category.csv", cat_agg.group_stats(["algorithm", "dataset", "attack_category"]), build_group_columns(["algorithm", "dataset", "attack_category"]))
    write_csv(output_dir / "results_grouped.csv", agg.group_stats(["algorithm", "dataset"]), build_group_columns(["algorithm", "dataset"]))
    print(f"Output: {output_dir}")


if __name__ == "__main__": main()
