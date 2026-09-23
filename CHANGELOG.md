# Changelog

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
