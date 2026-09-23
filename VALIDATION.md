# Validation

The public repository contains source and generated-input tests, not heap files,
decoded strings or private-capture reports. Run the commands below to create your
own synthetic evidence under ignored `captures/` and `artifacts/` directories.

## Checks run before initial publication

On 2026-09-23, Rust 1.96.0 on macOS ARM64 passed:

- `cargo fmt --all -- --check`
- `cargo clippy --locked --offline --all-targets -- -D warnings`
- `cargo test --release --locked --offline -- --include-ignored`: 35 tests passed
  (33 library tests and two CLI integration tests).
- The pinned Docker CLI build: 32 normal tests passed; three scale tests are
  deliberately skipped by its default test invocation and ran in release above.

Scale checks include 2,000,001 indexed/streamed candidates, a 2,000,001-String
trawl with a bounded verification reservoir, and a sparse 4 GiB+ file with an
object beyond the 32-bit offset boundary. These are resource-boundary tests,
not throughput benchmarks or proof of arbitrary heap correctness.

Other tests cover malformed inputs, wrong formats/profiles, field and array
bounds, capture mutation, overwrite refusal, owner-only String output, interrupted
streams, sample failure denominators, encoding fidelity, periodic metadata-like
patterns, header-width ambiguity, and node-prefix hash/link checks.

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
