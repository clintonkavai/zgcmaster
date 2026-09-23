#!/usr/bin/env python3
"""Build/run in Docker, capture a real memfd, and independently check recovered data.

Only orchestration uses host Python (standard library). Java, Maven and the CLI run
in containers. expected.json is a test oracle; the reader never reads its values.
"""
import argparse
import datetime
import gzip
import http.client
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def command(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f"Command failed: {' '.join(args)}\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    return result.stdout


def cli(*args):
    # Preserve owner-only output permissions without making files root-owned on Linux.
    identity = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    return command("docker", "compose", "run", "--rm", "-T", *identity, "cli", *map(str, args))


def build_images():
    # Only retry the idempotent image build, and only recognized transport errors.
    # Do not retry capture or output-producing commands after partial success.
    transient = ("502 Bad Gateway", "503 Service Unavailable", "429 Too Many Requests",
                 "TLS handshake timeout", "connection reset by peer")
    for attempt in range(3):
        try:
            command("docker", "compose", "build", "fixture", "cli")
            return
        except RuntimeError as error:
            if attempt == 2 or not any(message in str(error) for message in transient):
                raise
            print(f"Transient image transport failure; retry {attempt + 1}/2", flush=True)
            time.sleep(5 * (attempt + 1))


def request(base, path, method="GET"):
    with urllib.request.urlopen(urllib.request.Request(base + path, method=method), timeout=30) as response:
        return json.load(response)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--generational", action="store_true", help="Exercise compressed klass + generational ZGC")
    args = parser.parse_args()
    if args.generational:
        os.environ["COMPOSE_FILE"] = "compose.yaml:compose.generational.yaml"
    (ROOT / "captures").mkdir(exist_ok=True)
    (ROOT / "artifacts").mkdir(exist_ok=True)
    if not args.no_build:
        print("Building pinned fixture and CLI containers…", flush=True)
        build_images()
    command("docker", "compose", "up", "-d", "--no-build", "fixture")
    base = "http://127.0.0.1:" + os.environ.get("ZGCM_PORT", "18765")
    status = None
    for _ in range(60):
        try:
            status = request(base, "/fixture/status")
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException):
            time.sleep(1)
    check(status is not None, "Fixture did not become ready within 60 seconds")
    check(status["java"] == "21.0.11+10-LTS", "Unexpected JDK build")
    check(status["jmx_registered"] and status["jmx_sample_count"] == status["samples"], "JMX did not return the fixture count")
    check(any("ZGC" in gc for gc in status["collector"]), "ZGC is not active")
    trace = request(base, "/fixture/request", "POST")
    logs = command("docker", "compose", "logs", "--no-color", "--tail", "100", "fixture")
    check(f'trace_id={trace["trace_id"]}' in logs, "Logback trace correlation missing")
    check("Jetty started" in logs, "Expected Jetty runtime")
    cycles = request(base, "/fixture/gc-cycles", "POST")
    check(cycles["klass_layout_unchanged"], "Class identities changed across GC cycles")
    request(base, "/fixture/prepare", "POST")
    name = "demo-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    print(f"Capturing {name}…", flush=True)
    command("docker", "compose", "exec", "-T", "fixture", "bash", "/app/capture.sh", name)
    bundle = f"/captures/{name}"
    index = f"/artifacts/{name}.index.json"
    begin = time.monotonic()
    summary = json.loads(cli("scan", bundle, index))
    scan_seconds = time.monotonic() - begin
    oracle = json.loads((ROOT / "captures" / name / "expected.json").read_text())
    layout = json.loads((ROOT / "captures" / name / "layout.json").read_text())
    profile = "hotspot21-zgc-" + ("gen-compressedklass" if args.generational else "nongen-uncompressed") + "-le64"
    check(layout["profile"] == profile, "Effective GC/class-pointer flags differ from requested profile")
    templates = json.loads(cli("boot-profile", profile))
    actual_classes = {c["name"]: c for c in layout["classes"]}
    for template in templates["classes"]:
        actual = actual_classes[template["name"]]
        for key in ("size", "kind", "fields"):
            check(actual[key] == template[key], f"Boot layout mismatch: {template['name']} {key}")
        if template["kind"] == "array":
            for key in ("base", "scale", "length_offset", "element"):
                check(actual[key] == template[key], f"Boot array layout mismatch: {template['name']} {key}")
    # One invocation opens and hashes the capture once, then emits the selected objects.
    objects = [json.loads(line) for line in cli("dump", bundle, index, "lab.zgc.Fixture").splitlines()]
    samples = [o for o in objects if o["object"]["class"] == "lab.zgc.Fixture$Sample"]
    # Old copies may coexist. Prefer a candidate whose outgoing references resolve.
    samples.sort(key=lambda o: sum(isinstance(v, dict) and v.get("resolved", False) for v in o["fields"].values()))
    found = {o["fields"]["id"]: o for o in samples if 10000 <= o["fields"]["id"] < 10000 + oracle["sample_count"]}
    by_offset = {o["object"]["offset"]: o for o in samples}
    check(len(found) == oracle["sample_count"], "Did not recover all distinct sample IDs")
    for expected in oracle["samples"]:
        actual = found[expected["id"]]["fields"]
        for key in ("id", "quantity", "amount"):
            check(actual[key] == expected[key], f"Wrong recovered {key} for {expected['id']}")
        check(actual["active"] == {"value": expected["active"], "valid": True}, "Boolean mismatch")
        check(actual["label"].get("text") == expected["label"], "UTF-16 String mismatch")
        check(actual["next"]["target_class"] == "lab.zgc.Fixture$Sample", "Reference decoding failed")
        next_id = 10000 + (expected["id"] - 10000 + 1) % oracle["sample_count"]
        check(by_offset[actual["next"]["target_offset"]]["fields"]["id"] == next_id, "Wrong edge in linked record cycle")
    first = found[oracle["samples"][0]["id"]]
    first_expected = oracle["samples"][0]
    for field in ("measurements", "times"):
        view = json.loads(cli("show", bundle, index, first["fields"][field]["target_offset"]))
        check(view["preview"] == first_expected[field], f"Wrong {field} array values")
    output = f"/artifacts/{name}.payload.bin"
    extraction = json.loads(cli("extract", bundle, index, first["fields"]["payload"]["target_offset"], output))
    check(extraction["sha256"] == first_expected["payload_sha256"], "Extracted binary payload differs")
    # The Spring-managed fixture bean may have an inflated/unsupported monitor
    # header. The known sample graph also retains this shared payload directly.
    zipped = json.loads(cli("extract", bundle, index, first["fields"]["archive"]["target_offset"], f"/artifacts/{name}.gz"))
    check(zipped["sha256"] == oracle["gzip_sha256"], "Compressed payload hash differs")
    decoded = gzip.decompress((ROOT / "artifacts" / f"{name}.gz").read_bytes())
    check(decoded == b"zgcmaster: a binary payload recovered from a Java byte array\n" * 32, "Recovered gzip did not decode correctly")
    recovered_traces = [o for o in objects if o["object"]["class"] == "lab.zgc.Fixture$TraceEvent"]
    check(any(o["fields"]["traceId"].get("text") == trace["trace_id"] for o in recovered_traces), "Trace correlation record not recovered")
    # Capture completion also promises the JVM was resumed.
    check(request(base, "/fixture/status")["jmx_registered"], "Fixture did not resume")
    report = {"capture": name, "java": status["java"], "profile": profile, "heap_bytes": summary["heap_bytes"],
              "candidate_objects": summary["candidate_objects"], "samples_verified": len(found), "gc_cycles": cycles,
              "verified": ["primitive fields", "UTF-16 Strings", "object references", "int[]", "long[]",
                           "binary payload SHA-256", "gzip payload SHA-256 and decompression", "JMX", "Logback trace ID", "recovered trace event", "JVM resumed"],
              "trace_source": trace["trace_source"], "instana_backend_verified": False,
              "instana_trace_observed": trace["trace_source"] == "instana", "scan_seconds_including_container_start": round(scan_seconds, 3)}
    (ROOT / "artifacts" / f"{name}.evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print("Fixture is still running. Stop it with: docker compose stop fixture")


if __name__ == "__main__":
    main()
