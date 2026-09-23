# Changelog

## Unreleased

- `census`: byte-array format counts, printable bands and regional UTF-8 anomaly
  counts, with explicit whole-payload and prefix-only coverage. No tearing claims.
- `diff-captures`: bounded exact String-set differences, content census deltas,
  per-capture decode coverage and checksum-verified completion.
- `dictionaries`: streaming String key/value candidates across Node-compatible
  bindings, with key spread-hash checks, rejection counts and next-link labels.
- Bounded, versioned `--regex-pack` support in strings, dictionaries and corpus diffs.
- Synthetic tests for classification, rebased bindings, set semantics, resource
  limits, dictionary hash failures/cycles, malformed packs and private outputs.
- Linux fixture orchestration preserves invoking UID/GID for owner-only outputs;
  image builds retry recognized transient transport failures at most twice.
- Fixture raw-reference expectations are checked against captured mapping coverage;
  page remapping can invalidate offset hypotheses while mapped decoding still works.

## 0.1.0 — initial public source version

- Java 21 raw ZGC backing-file CLI; HPROF is intentionally not supported.
- Verified-bundle indexing, explicit boot bindings, filtered indexes and JSONL.
- Compressed/uncompressed klass layouts, generational/non-generational references.
- Periodicity-aware raw grouping and conservative profile suggestions.
- String trawling, seeded cached-hash verification and node-prefix proposals.
- Primitive-array extraction, array-constrained carving and structural count diffs.
- Docker-only Java 21 Spring Boot/Jetty fixture with JMX, traced Logback and
  optional Instana instrumentation. Real Instana backend delivery is not verified.
- Reproducible synthetic tests and GitHub Actions for both fixture modes.

This is experimental. No GC-root, retained-size, liveness, forwarding-state or
universal class-identification claims are made. No real captures are distributed.
