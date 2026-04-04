#!/usr/bin/env python3
"""Anomaly Detector - Z-score, IQR, and statistical methods for outlier detection."""

import statistics
import math
import json
import sys
import csv
import io


def z_score_detect(data: list[float], threshold: float = 2.5) -> list[dict]:
    """Detect anomalies using Z-score method."""
    if len(data) < 3:
        return []
    mean = statistics.mean(data)
    stdev = statistics.stdev(data)
    if stdev == 0:
        return []
    anomalies = []
    for i, val in enumerate(data):
        z = (val - mean) / stdev
        if abs(z) > threshold:
            anomalies.append({"index": i, "value": val, "z_score": round(z, 3), "method": "z-score"})
    return anomalies


def iqr_detect(data: list[float], multiplier: float = 1.5) -> list[dict]:
    """Detect anomalies using IQR (Interquartile Range) method."""
    if len(data) < 4:
        return []
    sorted_data = sorted(data)
    n = len(sorted_data)
    q1 = sorted_data[n // 4]
    q3 = sorted_data[3 * n // 4]
    iqr = q3 - q1
    lower = q1 - multiplier * iqr
    upper = q3 + multiplier * iqr
    anomalies = []
    for i, val in enumerate(data):
        if val < lower or val > upper:
            direction = "below" if val < lower else "above"
            anomalies.append({"index": i, "value": val, "bound": f"{direction} ({lower:.2f}, {upper:.2f})",
                            "method": "IQR"})
    return anomalies


def mad_detect(data: list[float], threshold: float = 3.0) -> list[dict]:
    """Detect anomalies using Median Absolute Deviation."""
    if len(data) < 3:
        return []
    median = statistics.median(data)
    mad = statistics.median([abs(x - median) for x in data])
    if mad == 0:
        return []
    anomalies = []
    for i, val in enumerate(data):
        modified_z = 0.6745 * (val - median) / mad
        if abs(modified_z) > threshold:
            anomalies.append({"index": i, "value": val, "modified_z": round(modified_z, 3), "method": "MAD"})
    return anomalies


def detect_all(data: list[float]) -> dict:
    """Run all anomaly detection methods and combine results."""
    z_anomalies = z_score_detect(data)
    iqr_anomalies = iqr_detect(data)
    mad_anomalies = mad_detect(data)

    all_indices = set()
    for a in z_anomalies + iqr_anomalies + mad_anomalies:
        all_indices.add(a["index"])

    consensus = []
    for idx in all_indices:
        methods = []
        if any(a["index"] == idx for a in z_anomalies): methods.append("z-score")
        if any(a["index"] == idx for a in iqr_anomalies): methods.append("IQR")
        if any(a["index"] == idx for a in mad_anomalies): methods.append("MAD")
        consensus.append({
            "index": idx, "value": data[idx],
            "detected_by": methods, "confidence": len(methods) / 3,
        })

    consensus.sort(key=lambda x: x["confidence"], reverse=True)
    return {
        "data_stats": {
            "count": len(data), "mean": round(statistics.mean(data), 2),
            "median": round(statistics.median(data), 2),
            "stdev": round(statistics.stdev(data), 2) if len(data) > 1 else 0,
            "min": min(data), "max": max(data),
        },
        "anomalies": {
            "z_score": z_anomalies, "iqr": iqr_anomalies, "mad": mad_anomalies,
        },
        "consensus": consensus,
        "total_anomalies": len(consensus),
    }


SAMPLE_DATA = [
    10, 12, 11, 13, 12, 11, 10, 12, 150, 11, 13, 12, 10, 11, 12,
    -50, 13, 11, 12, 10, 11, 200, 12, 13, 11, 10, 12, 11, 13, 12,
]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            reader = csv.reader(f)
            col = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            data = []
            for row in reader:
                try: data.append(float(row[col]))
                except (ValueError, IndexError): pass
    else:
        print("Using sample data with injected anomalies (150, -50, 200)\n")
        data = SAMPLE_DATA

    results = detect_all(data)

    print(f"Data Stats: {json.dumps(results['data_stats'], indent=2)}")
    print(f"\nConsensus Anomalies ({results['total_anomalies']} found):")
    for a in results["consensus"]:
        conf = "HIGH" if a["confidence"] >= 0.66 else "MEDIUM" if a["confidence"] >= 0.33 else "LOW"
        print(f"  Index {a['index']}: value={a['value']}, confidence={conf}, detected by: {', '.join(a['detected_by'])}")
