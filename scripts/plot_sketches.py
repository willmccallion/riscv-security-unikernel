"""Plots the sketch-lab CSVs in docs/sketches/data as SVGs in docs/sketches."""

import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("svg")
matplotlib.rcParams["svg.hashsalt"] = "sketch-lab"
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/sketches")
DATA = ROOT / "data"
KERNEL_SKETCH_BYTES = 1024 * 3 * 2


def rows(name):
    with open(DATA / name, newline="") as f:
        return list(csv.DictReader(f))


def style(ax, title, xlabel, ylabel):
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(frameon=False)


def error_vs_memory():
    series = defaultdict(list)
    for r in rows("cms_error_vs_memory.csv"):
        label = f"{r['update'].lower()} update, depth {r['depth']}"
        series[label].append((int(r["memory_bytes"]), float(r["mean_abs_error"])))
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for label, points in sorted(series.items()):
        points.sort()
        ax.plot(*zip(*points), marker="o", markersize=3, label=label,
                linestyle="-" if "conservative" in label else "--")
    ax.axvline(KERNEL_SKETCH_BYTES, color="grey", linewidth=1, linestyle=":")
    ax.text(KERNEL_SKETCH_BYTES * 1.08, ax.get_ylim()[1] * 0.5, "kernel (6 KB)", color="grey")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    style(ax, "Count-Min estimate error on a Zipf(1.1) stream",
          "sketch memory (bytes)", "mean overestimate (packets)")
    fig.tight_layout()
    fig.savefig(ROOT / "cms_error_vs_memory.svg", metadata={"Date": None})


def false_positives_vs_load():
    series = defaultdict(list)
    memory = {}
    for r in rows("cms_detector_vs_load.csv"):
        series[r["config"]].append((float(r["load_pps"]), 100 * float(r["false_positive_rate"])))
        memory[r["config"]] = int(r["memory_bytes"])
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for label, points in series.items():
        points.sort()
        previous = label.startswith("previous")
        size = f"{memory[label] // 1024} KB" if memory[label] >= 1024 else f"{memory[label]} B"
        ax.plot(*zip(*points), marker="o", markersize=3,
                label=f"{label} ({size})",
                color="black" if previous else None,
                linewidth=2.5 if previous else 1.5,
                linestyle="--" if previous else "-")
    ax.set_xscale("log")
    style(ax, "Legitimate sources banned as total traffic grows",
          "total traffic (packets per second)", "legitimate sources banned (%)")
    fig.tight_layout()
    fig.savefig(ROOT / "cms_false_positives_vs_load.svg", metadata={"Date": None})


error_vs_memory()
false_positives_vs_load()
print(f"wrote charts to {ROOT}")
