#!/usr/bin/env python3
"""Exercise new CLI paths on an existing fixture capture (Docker CLI only)."""
import argparse
import datetime
import json
from pathlib import Path
from demo import ROOT, cli, check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", help="Directory name under captures/")
    args = parser.parse_args()
    name = args.capture
    check(Path(name).name == name and name not in (".", ".."), "Use a capture directory name")
    layout = json.loads((ROOT / "captures" / name / "layout.json").read_text())
    classes = {c["name"]: c for c in layout["classes"]}
    prefix = "features-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    bundle = f"/captures/{name}"
    filtered = f"/artifacts/{prefix}.filtered.json"
    streamed = f"/artifacts/{prefix}.stream-summary.json"
    jsonl = f"/artifacts/{prefix}.objects.jsonl"
    sample = "lab.zgc.Fixture$Sample"
    a = json.loads(cli("scan", bundle, filtered, "--only", sample))
    b = json.loads(cli("scan", bundle, streamed, "--only", sample, "--jsonl", jsonl))
    check(a["class_counts"] == b["class_counts"], "Stream/filter counts differ")
    check(b["indexed_objects"] == 0, "Streaming retained object entries")
    rows = [json.loads(line) for line in (ROOT / "artifacts" / f"{prefix}.objects.jsonl").read_text().splitlines()]
    check(rows[-1]["record"] == "complete", "Missing stream completion footer")
    check(len(rows) - 1 == a["candidate_objects"], "Stream row count mismatch")
    delta = json.loads(cli("diff", filtered, streamed))
    check(delta["class_counts"][sample]["delta"] == 0, "Same capture diff is nonzero")
    raw_index = f"/artifacts/{prefix}.raw-typed.json"
    names = ["[B", "[I", "[J", "java.lang.String", "java.util.ArrayList", "java.util.HashMap$Node"]
    bindings = [arg for n in names for arg in ("--bind", f"{n}={classes[n]['klass']}")]
    raw = json.loads(cli("scan-raw", bundle + "/heap.raw", raw_index, "--identity-mapping",
                         "--boot-profile", layout["profile"], *bindings))
    check(raw["identity_mapping"], "Identity mode not recorded")
    records = [json.loads(row) for row in cli("list", raw_index, "java.util.HashMap$Node").splitlines()]
    check(records, "No nodes recovered using the boot library")
    node = json.loads(cli("show", bundle + "/heap.raw", raw_index, records[0]["offset"]))
    for field in ("key", "value", "next"):
        ref = node["fields"][field]
        check(ref is None or (not ref["resolved"] and ref["target_offset"] is None), "Identity mode resolved a reference")
    directory = f"/artifacts/{prefix}.carved"
    carved = [json.loads(row) for row in cli("carve", bundle + "/heap.raw", raw_index, directory).splitlines()]
    oracle = json.loads((ROOT / "captures" / name / "expected.json").read_text())
    check(any(row["extraction"]["sha256"] == oracle["gzip_sha256"] for row in carved), "Array carving did not recover fixture gzip")
    raw_stats = json.loads(cli("scan-raw", bundle + "/heap.raw", f"/artifacts/{prefix}.raw-stats.json", "--discover-bindings"))
    detection = raw_stats["profile_detection"]
    discovered = raw_stats["binding_discovery"]
    expected_bindings = {n: classes[n]["klass"] for n in ("java.lang.String", "[B")}
    expected_model = ("nongen-low42-equals-file-offset" if "-nongen-" in layout["profile"] else
                      "gen-" + layout["architecture"] + "-heap-relative-equals-file-offset")
    check(any(p["bindings"] == expected_bindings and p["profile_assumption"] == layout["profile"]
              and p["reference_hypothesis"] == expected_model and not p["automatically_applied"]
              for p in discovered["proposals"]), "Discovery proposals did not match independent fixture metadata")
    nodes = discovered["hashmap_node_discovery"]["proposals"]
    check(any(p["bindings"]["java.util.HashMap$Node"] == classes["java.util.HashMap$Node"]["klass"]
              and p["reference_hypothesis"] == expected_model and not p["automatically_applied"]
              for p in nodes), "Node-prefix proposals did not include the independent fixture Node ID")
    string_options = ["--boot-profile", layout["profile"], "--reference-hypothesis", expected_model]
    string_options += [arg for n, identity in expected_bindings.items() for arg in ("--bind", f"{n}={identity}")]
    strings_file = f"{prefix}.strings.jsonl"
    trawl = json.loads(cli("strings", bundle + "/heap.raw", *string_options, "--min-len", "8",
                          "--output", f"/artifacts/{strings_file}"))
    expected_labels = {s["label"] for s in oracle["samples"]}
    found_labels = set()
    emitted = 0
    last = None
    with (ROOT / "artifacts" / strings_file).open() as stream:
        for line in stream:
            last = json.loads(line)
            if last["record"] == "string":
                emitted += 1
                check(last["hash_status"] != "mismatch", "Trawl emitted a mismatched hash")
                if last["text"] in expected_labels:
                    found_labels.add(last["text"])
    check(found_labels == expected_labels, "Trawl missed fixture UTF-16 labels")
    check(last == trawl and emitted == trawl["emitted"], "Trawl footer/counts differ")
    check(trawl["heap_sha256"] == raw_stats["heap_sha256"], "Trawl capture hash differs")
    verification = json.loads(cli("verify-bindings", bundle + "/heap.raw", *string_options,
                                  "--samples", "1000", "--seed", "20260923", "--output", f"/artifacts/{prefix}.verify.json"))
    check(verification["confirmed_cached_pairs"] > 0, "No hash-confirmed sampled pairs")
    check(sum(verification["counts"].values()) == verification["sampling"]["sampled"], "Verification omitted failures from counts")
    check(verification["heap_sha256"] == trawl["heap_sha256"], "Verification capture hash differs")
    report = {"capture": name, "profile": layout["profile"], "filtered_candidates": a["candidate_objects"],
              "stream_rows": len(rows) - 1, "bound_boot_counts": raw["class_counts"], "carved_candidates": len(carved),
              "verified": ["filtered indexing", "streaming footer/counts", "diff parity", "boot bindings without layout/maps sidecar",
                           "maps-free unresolved references", "array-constrained gzip carving",
                           "String/byte[] discovery matches independent fixture IDs and reference model",
                           "Node-prefix discovery includes independent fixture Node ID",
                           "raw trawl recovers every expected UTF-16 label with checksummed JSONL",
                           "verification reports sampled failures and confirmed pairs without text"],
              "profile_detection": detection, "binding_discovery": discovered, "trawl": trawl,
              "trawl_fixture_labels": len(found_labels), "verification": verification}
    (ROOT / "artifacts" / f"{prefix}.evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
