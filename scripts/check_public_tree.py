#!/usr/bin/env python3
"""Reject obvious capture/secret material in tracked files; not a complete secret scanner."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DENIED_DIRS = {"captures", "artifacts", "target", "__pycache__"}
DENIED_NAMES = {"STRING-VALIDATION.md", "PERIODICITY-VALIDATION.md", "maps.txt", "jvm-arguments.txt"}
DENIED_SUFFIXES = (".raw", ".bin", ".hprof", ".jsonl", ".pem", ".key", ".p12", ".jks", ".pyc", ".index.json", ".evidence.json")
PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "personal absolute path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "private capture filename": re.compile(rb"\bfd[0-9]+_fresh_[0-9]{8}\.bin\b"),
}


def main():
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    files = [Path(p.decode()) for p in raw.split(b"\0") if p]
    if not files:
        raise SystemExit("No tracked files; stage the intended public tree before checking")
    failures = []
    for path in files:
        name = path.name
        if (set(path.parts) & DENIED_DIRS or path.parts[:2] == ("docs", "private")
                or name in DENIED_NAMES or name.startswith(".env")
                or name.endswith(DENIED_SUFFIXES)):
            failures.append(f"{path}: private/generated path")
            continue
        actual = ROOT / path
        if actual.is_symlink():
            failures.append(f"{path}: symlinks need explicit publication review")
            continue
        if actual.stat().st_size > 1024 * 1024:
            failures.append(f"{path}: over 1 MiB; unexpected source artifact")
            continue
        data = actual.read_bytes()
        if b"\0" in data:
            failures.append(f"{path}: binary content")
        for label, pattern in PATTERNS.items():
            if pattern.search(data):
                failures.append(f"{path}: possible {label}")
    if failures:
        raise SystemExit("Public tree check failed (contents withheld):\n" + "\n".join(failures))
    print(f"Public tree check passed: {len(files)} source/documentation files; no capture artifacts detected")


if __name__ == "__main__":
    main()
