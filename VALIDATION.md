# Validation

The public repository contains source and generated-input tests, not heap files,
decoded strings or private-capture reports. Run the commands below to create your
own synthetic evidence under ignored `captures/` and `artifacts/` directories.

## Rust and orchestration checks

On 2026-09-23, Rust 1.96.0 on macOS ARM64 passed:

- `cargo fmt --all -- --check`
- `cargo clippy --locked --offline --all-targets -- -D warnings`
- `cargo test --release --locked --offline -- --include-ignored`: 42 tests passed
  (39 library tests and three CLI integration tests).
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: six tests passed.
- The pinned Docker CLI build: 39 normal tests passed; three scale tests are
  deliberately skipped by its default test invocation and ran in release above.

Scale checks include 2,000,001 indexed/streamed candidates, a 2,000,001-String
trawl with a bounded verification reservoir, and a sparse 4 GiB+ file with an
object beyond the 32-bit offset boundary. These are resource-boundary tests,
not throughput benchmarks or proof of arbitrary heap correctness.

Other tests cover malformed inputs, wrong formats/profiles, field and array
bounds, capture mutation, overwrite refusal, owner-only String output, interrupted
streams, sample failure denominators, encoding fidelity, periodic metadata-like
patterns, header-width ambiguity, and node-prefix hash/link checks. Corpus tests
cover content-policy boundaries, complete-payload versus prefix-only coverage,
per-region anomalies, exact new/gone sets, rebased IDs, regex labels and bounds,
resource-limit refusal and String key/value extraction with corrupt hashes/links.

## Java fixture evidence

Both modes have been exercised in Linux ARM64 Docker containers with pinned
Temurin 21.0.11+10-LTS and a 256 MiB heap:

| Mode | Class pointers | Independently checked records | Raw-trawl labels recovered |
|---|---|---:|---:|
| Non-generational ZGC | uncompressed | 256/256 | 256/256 |
| Generational ZGC | compressed | 256/256 | 256/256 |

The fixture checked primitive fields, UTF-16 labels, all edges of a retained
record cycle, int/long boundary values, primitive payload checksums, gzip
decompression, JMX counts, traced Logback output and successful JVM resume after
capture. The six boot templates matched independently exported fixture layouts.
Bounded allocation pressure and explicit GC requests exercised changing reference
colors; class identities/layouts remained unchanged in these runs.

The raw feature workflow checked streaming/filter count parity, structural diffs,
unresolved identity-mode references, array-constrained carving, discovered
String/byte[] IDs and reference hypotheses, and inclusion of the independently
known HashMap.Node ID in prefix proposals. Raw discovery receives no class sidecar;
its proposed IDs are checked against fixture metadata afterward.

The 256/256 raw-label results above describe the initial publication captures,
not a guarantee across GC states. A subsequent non-generational capture recovered
all 256 labels with maps but only 150 with the raw-offset hypothesis. A concrete
backing reference's low-42-bit offset was outside the backing file, while its
captured mapping resolved it inside the file: physical pages had been remapped.
Raw methods correctly rejected that reference rather than inventing a target.

Feature checks now require every **map-eligible** expected raw String/dictionary
pair, independently checking whether the explicit raw hypothesis agrees with
captured maps. Full mapped sample checks still require all 256 records. The fixture
also retains 16 String/String dictionary pairs; mapped decoding must recover all
16. Evidence separately reports raw-eligible and actually recovered counts; zero
eligible pairs would not establish raw dictionary recovery on that capture.
The raw commands never receive the oracle mappings or expected values. Python
tests cover nonidentity page mappings and both generational pointer encodings.

Additional feature checks reconcile all census buckets, detect the fixture gzip,
verify a corpus self-diff has no changes, and check dictionary completion/counts.
Generated-byte tests supply the positive two-capture changes; a self-diff alone
is not evidence of detecting real incidents or restarts.

On the two new Linux ARM64 captures, the completed feature checks measured:

| Mode | Raw labels eligible / recovered | Dictionary pairs mapped / raw eligible / recovered |
|---|---:|---:|
| Non-generational, uncompressed klass | 150 / 150 | 16 / 16 / 16 |
| Generational, compressed klass | 256 / 256 | 16 / 16 / 16 |

Both complete mapped sample-graph checks remained 256/256. Both corpus self-diffs
had zero new/gone strings and zero per-format count/byte deltas.

Reproduce with Docker Compose v2 and Python 3.10+:

```sh
python3 scripts/ci_fixture.py --profile nongen
python3 scripts/ci_fixture.py --profile generational
```

Run sequentially in a local workspace. The wrapper stops its fixture even if a
check fails. Java and Maven run only inside Docker; no host Java configuration is
changed. Machine-readable evidence is generated as `artifacts/*.evidence.json`.

## CI and limits

[GitHub Actions](https://github.com/clintonkavai/zgcmaster/actions/workflows/ci.yml)
is configured to run the Rust/static checks and both fixture modes on Linux AMD64
for pushes and pull requests. Consult the actual run status for evidence at a
particular revision. Only synthetic evidence reports are uploaded; heap captures,
strings and extracted payloads are excluded.

The reader does not verify GC roots, retained sizes, liveness, forwarding state,
every JDK/flag combination, or all application layouts. Reference hypotheses can
fail on arbitrary captures. Hash matches do not establish exact class identity;
node-compatible classes remain ambiguous. Discovery is bounded and reports
truncated coverage. The optional real Instana agent/backend has not been verified;
the default fixture uses SDK hooks and explicitly local trace IDs.
