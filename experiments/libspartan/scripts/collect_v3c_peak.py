#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "v3c_peak"


def read_jsonl(path):
    if not path.exists():
        return []
    records = []
    for line in path.read_text(errors="replace").splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def classify(component):
    text = component.lower()
    if "sumcheck" in text:
        return "active Sumcheck folded tables"
    if "product" in text:
        return "active product-layer tables"
    if "dense" in text or "witness" in text:
        return "dense MLE inputs"
    if "sparse" in text:
        return "sparse polynomial structures"
    if "r1cs" in text or "instance" in text or "relation" in text:
        return "R1CS/relation objects"
    if "commitment" in text:
        return "commitment scalar layouts"
    if "pbmo" in text:
        return "PBMO objects"
    return "runtime and allocator overhead"


def allocation_record(event):
    component = event.get("logical_component", "unknown")
    return {
        "allocation_id": event["allocation_id"],
        "source_file": event.get("source_file"),
        "function": event.get("function"),
        "logical_operator": component,
        "table_or_polynomial_identity": component,
        "layer_identity": None,
        "sumcheck_round": None,
        "scalar_count": event.get("requested_bytes", 0) // 32
        if event.get("element_type") == "Scalar"
        else None,
        "logical_bytes": event.get("requested_bytes"),
        "allocated_capacity_bytes": event.get("actual_capacity_bytes"),
        "creation_point_ns": event.get("timestamp_ns"),
        "last_use_point_ns": None,
        "number_of_future_reads": None,
        "access_pattern": None,
        "mutable": None,
        "privacy": event.get("privacy"),
        "replayable": event.get("replayable"),
        "spillable": event.get("streamable"),
        "recomputable": event.get("replayable"),
        "duplicate_equivalent_object_id": None,
        "transcript_dependency": None,
        "category": classify(component),
    }


def analyze(mode, cap):
    prefix = RESULTS / f"{mode}_18_{cap}"
    trace = read_jsonl(prefix.with_suffix(".alloc.jsonl"))
    resident = read_jsonl(prefix.with_suffix(".resident.jsonl"))
    run = json.loads(prefix.with_suffix(".run.json").read_text())
    started = next((e for e in trace if e.get("event") == "trace_started"), None)
    if not resident or not started:
        return {"cap": cap, "run": run, "peak": None, "error": "missing trace or resident samples"}
    valid_samples = [s for s in resident if isinstance(s.get("vm_rss_kib"), int)]
    def live_cut(sample):
        relative_ns = sample["timestamp_epoch_ns"] - started["epoch_ms"] * 1_000_000
        live = {}
        for event in trace:
            timestamp = event.get("timestamp_ns")
            if timestamp is None or timestamp > relative_ns:
                continue
            if event.get("event") == "allocation_created":
                live[event["allocation_id"]] = event
            elif event.get("event") == "allocation_destroyed":
                live.pop(event["allocation_id"], None)
        records = [allocation_record(event) for event in live.values()]
        records.sort(key=lambda item: item["logical_bytes"] or 0, reverse=True)
        categories = defaultdict(int)
        for record in records:
            categories[record["category"]] += record["logical_bytes"] or 0
        tracked = sum(item["logical_bytes"] or 0 for item in records)
        return {
            "sample": sample,
            "relative_peak_ns": relative_ns,
            "tracked_live_bytes": tracked,
            "untracked_rss_bytes": sample["vm_rss_kib"] * 1024 - tracked,
            "decomposition_bytes": dict(sorted(categories.items())),
            "top_twenty_allocations": records[:20],
            "all_live_allocations": records,
        }

    peak = max(valid_samples, key=lambda item: item["vm_rss_kib"])
    process_cut = live_cut(peak)
    after_prove = next(
        (
            event for event in trace
            if event.get("event") == "snapshot"
            and event.get("stage") == "patched.after_prove"
        ),
        None,
    )
    prover_cut = None
    if after_prove:
        cutoff = started["epoch_ms"] * 1_000_000 + after_prove["timestamp_ns"]
        prover_samples = [
            sample for sample in valid_samples
            if sample["timestamp_epoch_ns"] <= cutoff
        ]
        if prover_samples:
            prover_cut = live_cut(max(prover_samples, key=lambda item: item["vm_rss_kib"]))
    return {
        "cap": cap,
        "run": run,
        "peak": peak,
        "trace_alignment_uncertainty_ns": 1_000_000,
        "relative_peak_ns": process_cut["relative_peak_ns"],
        "tracked_live_bytes": process_cut["tracked_live_bytes"],
        "untracked_rss_bytes": process_cut["untracked_rss_bytes"],
        "decomposition_bytes": process_cut["decomposition_bytes"],
        "top_twenty_allocations": process_cut["top_twenty_allocations"],
        "all_live_allocations": process_cut["all_live_allocations"],
        "prover_peak": prover_cut,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("FS3", "FS4"), default="FS3")
    parser.add_argument("--caps", nargs="+", default=("512", "640", "uncapped"))
    parser.add_argument("--output")
    args = parser.parse_args()
    output = Path(args.output) if args.output else (
        ROOT.parent / "v3c_memory" / f"{args.mode.lower()}_peak_live_cut.json"
    )
    data = {
        "experiment": f"phase_v3c_{args.mode.lower()}_peak_live_cut",
        "status": "MEASURED_WITH_1MS_TRACE_ALIGNMENT_UNCERTAINTY",
        "runs": [analyze(args.mode, cap) for cap in args.caps],
        "notes": [
            "Null semantic fields are not inferred when the allocator trace has no reliable source.",
            "Tracked allocation bytes exclude allocations below the configured 64 KiB threshold.",
            "This is an implementation peak attribution, not a cryptographic lower bound.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n")
    json.loads(output.read_text())
    print(output)


if __name__ == "__main__":
    main()
