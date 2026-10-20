"""Statistics for controlled serial/parallel/auto analyzer benchmarks."""
import math
from collections import defaultdict

def summarize_performance(runs):
    if not runs:
        raise ValueError("Empty input")
    byMode = defaultdict(list)
    for r in runs:
        if not isinstance(r, dict):
            raise ValueError("Non-dict row")
        mode = r.get("mode")
        if mode not in ("serial", "parallel", "auto"):
            raise ValueError("Unknown mode")
        wall = r.get("wallSeconds")
        if isinstance(wall, bool) or not isinstance(wall, (int, float)) or not math.isfinite(wall) or wall <= 0:
            raise ValueError("Invalid wallSeconds")
        peak = r.get("peakGroupRssMiB")
        if isinstance(peak, bool) or not isinstance(peak, (int, float)) or not math.isfinite(peak) or peak < 0:
            raise ValueError("Invalid peakGroupRssMiB")
        byMode[mode].append((wall, peak))
    if "serial" not in byMode or "parallel" not in byMode:
        raise ValueError("Missing serial or parallel")
    out = {}
    for mode, pairs in byMode.items():
        out[mode] = {"runs": len(pairs), "meanSeconds": sum(w for w, _ in pairs) / len(pairs), "peakGroupRssMiB": max(p for _, p in pairs)}
    serialMean = out["serial"]["meanSeconds"]
    parallelMean = out["parallel"]["meanSeconds"]
    return {"byMode": out, "serialMeanSeconds": serialMean,
            "parallelMeanSeconds": parallelMean, "speedup": serialMean / parallelMean,
            "wallTimeReductionPercent": 100 * (1 - parallelMean / serialMean)}
