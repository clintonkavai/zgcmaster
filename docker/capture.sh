#!/usr/bin/env bash
# Stops only this container's fixture JVM; the shell stays runnable to resume it.
set -euo pipefail
name=${1:-sample}
[[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'Use a simple capture name.' >&2; exit 2; }
dest="/captures/$name"
[[ ! -e "$dest" ]] || { echo "Capture already exists: $dest" >&2; exit 2; }
pid=$(< /tmp/fixture.pid)
[[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || { echo 'Missing isolated JVM PID.' >&2; exit 2; }
[[ -s /tmp/fixture/layout.json ]] || { echo 'Fixture not ready.' >&2; exit 2; }
mkdir -p "$dest"
resume() { kill -CONT "$pid" 2>/dev/null || true; }
trap resume EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
kill -STOP "$pid"
stopped=false
for i in {1..100}; do
  if awk '$1 == "State:" && ($2 == "T" || $2 == "t") { found=1 } END { exit !found }' "/proc/$pid/status"; then stopped=true; break; fi
  sleep 0.02
done
$stopped || { echo 'JVM did not stop.' >&2; exit 1; }
fd=''
for candidate in /proc/"$pid"/fd/*; do
  link=$(readlink "$candidate" || true)
  if [[ "$link" == /memfd:java_heap* ]]; then
    [[ -z "$fd" ]] || { echo 'Multiple backing files; unsupported profile.' >&2; exit 1; }
    fd="$candidate"
  fi
done
[[ -n "$fd" ]] || { echo 'ZGC memfd not found.' >&2; exit 1; }
cp "/proc/$pid/maps" "$dest/maps.txt"
cp /tmp/fixture/layout.json /tmp/fixture/expected.json "$dest/"
cp /tmp/fixture/gc.log "$dest/"
tr '\0' '\n' < "/proc/$pid/cmdline" > "$dest/jvm-arguments.txt"
cp --sparse=always "$fd" "$dest/heap.raw.partial"
mv "$dest/heap.raw.partial" "$dest/heap.raw"
resume
trap - EXIT INT TERM
printf 'process-stopped; arbitrary GC phase; roots and forwarding state not captured\n' > "$dest/consistency.txt"
(cd "$dest" && sha256sum heap.raw layout.json maps.txt expected.json consistency.txt > SHA256SUMS)
printf 'Captured %s from %s (JVM resumed)\n' "$dest" "$fd"
