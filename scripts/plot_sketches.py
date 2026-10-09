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
KERNEL_SOURCE_REGISTERS = 256


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


def hll_error_vs_registers():
    series = defaultdict(list)
    predicted = {}
    for r in rows("hll_error_vs_registers.csv"):
        m = int(r["registers"])
        series[int(r["distinct"])].append((m, 100 * float(r["rms_relative_error"])))
        predicted[m] = 100 * float(r["predicted_standard_error"])
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for distinct, points in sorted(series.items()):
        points.sort()
        ax.plot(*zip(*points), marker="o", markersize=3, label=f"{distinct:,} distinct")
    ax.plot(*zip(*sorted(predicted.items())), color="black", linestyle="--", label="predicted 1.04/\u221am")
    ax.axvline(KERNEL_SOURCE_REGISTERS, color="grey", linewidth=1, linestyle=":")
    ax.text(KERNEL_SOURCE_REGISTERS * 1.08, ax.get_ylim()[1] * 0.8, "kernel (256)", color="grey")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    style(ax, "HyperLogLog error by register count (40 keys each)",
          "registers (one byte each)", "RMS relative error (%)")
    fig.tight_layout()
    fig.savefig(ROOT / "hll_error_vs_registers.svg", metadata={"Date": None})


def port_scans_vs_load():
    false_positives = defaultdict(list)
    caught = defaultdict(list)
    for r in rows("port_scans_vs_load.csv"):
        sources = int(r["sources_per_window"])
        false_positives[r["config"]].append((sources, 100 * float(r["false_positive_rate"])))
        caught[r["config"]].append((sources, 100 * float(r["caught_100_port_scans"])))
    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 4.2))
    for label in false_positives:
        engine = label.startswith("engine")
        line = dict(marker="o", markersize=3, label=label,
                    color="black" if engine else None, linewidth=2.5 if engine else 1.5)
        left.plot(*zip(*sorted(false_positives[label])), **line)
        right.plot(*zip(*sorted(caught[label])), **line)
    for ax in (left, right):
        ax.set_xscale("log")
    style(left, "Ordinary sources banned as scanners",
          "sources per five-second window", "ordinary sources banned (%)")
    style(right, "100-port scans caught",
          "sources per five-second window", "scanners caught (%)")
    right.set_ylim(0, 105)
    fig.tight_layout()
    fig.savefig(ROOT / "port_scans_vs_load.svg", metadata={"Date": None})


def subnet_false_bans_vs_load():
    series = defaultdict(list)
    memory = {}
    for r in rows("subnet_floods_vs_load.csv"):
        series[r["config"]].append((float(r["load_pps"]), int(r["legit_banned_by_subnet"])))
        memory[r["config"]] = int(r["memory_bytes"])
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for label, points in series.items():
        kernel = label.startswith("kernel")
        size = f"{memory[label] / 1024:g} KB"
        ax.plot(*zip(*sorted(points)), marker="o", markersize=3, label=f"{label} ({size})",
                color="black" if kernel else None, linewidth=2.5 if kernel else 1.5)
    ax.set_xscale("log")
    style(ax, "Legitimate sources caught in a subnet ban (six runs)",
          "total traffic (packets per second)", "legitimate sources banned")
    fig.tight_layout()
    fig.savefig(ROOT / "subnet_false_bans_vs_load.svg", metadata={"Date": None})


error_vs_memory()
false_positives_vs_load()
hll_error_vs_registers()
port_scans_vs_load()
subnet_false_bans_vs_load()
print(f"wrote charts to {ROOT}")
