#!/usr/bin/env python3
"""Run the synthetic demo and feature checks; always stop this project's fixture."""
import argparse
import subprocess
import sys
from demo import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("nongen", "generational"), required=True)
    args = parser.parse_args()
    captures = ROOT / "captures"
    captures.mkdir(exist_ok=True)
    before = {p.name for p in captures.iterdir() if p.is_dir()}
    demo = [sys.executable, "scripts/demo.py"]
    if args.profile == "generational":
        demo.append("--generational")
    try:
        subprocess.run(demo, cwd=ROOT, check=True, timeout=1200)
        created = sorted(p.name for p in captures.iterdir() if p.is_dir() and p.name not in before)
        if len(created) != 1:
            raise RuntimeError(f"Expected one new synthetic capture, found {len(created)}")
        subprocess.run([sys.executable, "scripts/check_features.py", created[0]], cwd=ROOT,
                       check=True, timeout=600)
    finally:
        subprocess.run(["docker", "compose", "stop", "fixture"], cwd=ROOT,
                       check=True, timeout=60)


if __name__ == "__main__":
    main()
