# Census, corpus diffs and dictionaries

These commands analyze candidate objects, not proven live heap contents. Use the
same capture procedure and analysis options when comparing snapshots. Class
bindings and reference hypotheses remain explicit; no registry or automatic
rebinding is implemented.

Examples below use a native `zgcmaster` installed with `cargo install --path .
--locked`. For Docker, prefix commands with `docker compose run --rm -T --user
"$(id -u):$(id -g)" cli` and use `/captures/` and `/artifacts/` paths. Running as
your Unix UID lets you read owner-only output files on Linux. Neither workflow
needs host Java.

## Prepare a small typed index

First run `scan-raw --discover-bindings`, review its proposals and use
`verify-bindings` to measure them. Use only bindings appropriate to this capture.
Replace the placeholders below with the reviewed values:

```sh
zgcmaster scan-raw captures/before.raw artifacts/before.index.json \
  --identity-mapping --boot-profile PROFILE \
  --bind 'java.lang.String=STRING_KLASS' --bind '[B=BYTE_ARRAY_KLASS' \
  --only 'java.lang.String,[B'
```

Repeat for the later capture, producing `artifacts/after.index.json`. IDs can
differ between captures. Built-in layouts are not class-identity evidence.

`census` needs an index containing `[B`; `diff-captures` needs both String and
`[B`. An ordinary verified bundle index also works. Streaming summary indexes
contain no object vector and are refused: make a filtered index instead. The
existing two-million-object index cap still applies to these two commands.
`dictionaries`, like `strings`, scans directly and has no object-vector cap.

## Byte-array census

```sh
zgcmaster census captures/before.raw artifacts/before.index.json \
  --output artifacts/before.census.json
```

The JSON `formats` table has candidate counts and payload-byte totals. Every
indexed byte array contributes to exactly one format bucket, including empty
and explicitly unclassified arrays. No content deduplication is applied.

Classification priority:

1. Payload-start signatures: JPEG, PNG, GIF, gzip, ZIP and PDF. These are format
   hints, not successful decoding of the entire format. Scratch-space signatures,
   PEM text markers and a bare JKS magic word do not qualify.
2. A complete UTF-8 JSON object/array accepted by the JSON parser; scalar JSON
   values are not a separate category. The parser's recursion limit applies.
3. Invalid UTF-8 with at least 80% printable characters: `text-like-invalid-utf8`.
4. Valid UTF-8 with at least 95% printable characters: `text`.
5. At least 80% printable: `mixed`; otherwise `binary`.

Printable ratios count Unicode scalar values after lossy UTF-8 decoding.
Replacement characters and controls other than TAB/CR/LF are non-printable.
Separate bands are 0–50%, 50–80%, 80–95% and 95–100%. The JSON report records this
policy and its version, so counts can be compared under the same rules.

Full-payload UTF-8/JSON analysis is limited by `--max-bytes` (default and maximum
1 MiB). Larger arrays still receive a magic hint from at most 32 payload bytes;
others enter `unclassified-over-limit`. `coverage` reports full-payload coverage,
over-limit counts, prefix-only magic counts, and unclassified counts. Nothing
silently truncates a payload and then calls it broken UTF-8.

`utf8_status` distinguishes valid data, an incomplete final character, and an
invalid sequence. `regions` groups arrays by header start in 64 MiB file-offset
regions by default (`--region-bytes`: 16 MiB–1 GiB). It reports text-like encoding
anomalies per region. These are **not measured GC-tearing rates**: Latin-1,
UTF-16, binary data, deliberate truncation and stale copies are alternatives.

Counts include overlapping candidates and old copies. Summed payload bytes are
not occupied heap size. This command does not parse JSON field vocabularies.

## Exact String-set differences

```sh
zgcmaster diff-captures captures/before.raw artifacts/before.index.json \
  captures/after.raw artifacts/after.index.json \
  --reference-hypothesis MODEL --min-len 8 \
  --regex-pack examples/regex-pack.example.json \
  --output artifacts/changes.jsonl
```

Choose `MODEL` from the binding proposal you reviewed:

- `nongen-low42-equals-file-offset`
- `gen-amd64-heap-relative-equals-file-offset`
- `gen-aarch64-heap-relative-equals-file-offset`

The stream contains metadata, `string-change` rows (`change: new` or `gone`),
and a completion footer. Text is deduplicated within each capture. Rows carry
the text, first candidate offset, candidate occurrence count and regex labels.
Unchanged text is not emitted, even if its duplicate count changes. Ordering is
deterministic: new strings sorted by text, then gone strings sorted by text.

The footer includes both censuses, per-format count/byte deltas, new/gone/unchanged
String counts, regex-hit counts for changed texts, decode rejection counts,
binding assumptions and limits. Both heap checksums are verified before reading
and rechecked before the completion footer. Require that footer before consuming
a diff as complete.

Profiles, JDK labels, architectures and identity modes must match; klass IDs may
differ. The caller still owns capture comparability. Indexed String/byte[] layouts
must match the supported boot templates. An explicit reference hypothesis is
required even for a bundle: this command does not silently substitute `/proc`
mapping behavior for the selected hypothesis.

Cached-hash mismatches and lossy UTF-16 strings are excluded. Unhashed Strings
are allowed and counted unless `--require-hash` is set. `--min-len` counts UTF-16
units. `--max-bytes` also limits String backing payloads; skipped/failed candidates
are accounted for, not silently considered absent from the whole JVM.

Default per-capture bounds are 250,000 unique strings and 64 MiB of stored UTF-8
text. Increase `--max-unique` (maximum 2,000,000) and `--max-text-bytes` (maximum
512 MiB) explicitly when needed. These are text bounds, not total process-memory
limits: maps, indexes and decoding need additional memory. Only one index is
loaded at a time, but both String sets are retained. Exceeding a corpus bound
fails before emitting a diff instead of inventing disappearance from truncation.

New error text can help investigate incidents, but new/gone is only candidate-set
presence, not proof of an incident, restart, allocation or deletion. Missing
references and stale copies affect the results. Regex matches in unchanged text
are not new hits.

## String-to-String dictionary candidates

```sh
zgcmaster dictionaries captures/after.raw \
  --boot-profile PROFILE --reference-hypothesis MODEL \
  --bind 'java.lang.String=STRING_KLASS' --bind '[B=BYTE_ARRAY_KLASS' \
  --node-klass NODE_KLASS --node-klass ANOTHER_NODE_KLASS \
  --regex-pack examples/regex-pack.example.json \
  --output artifacts/dictionaries.jsonl
```

Supply one or more reviewed Node-compatible IDs (up to 64); omit the second
`--node-klass` when unnecessary. Each header is visited once. Key/value String
headers, backing arrays, bounds, encodings and cached hashes are checked. The
computed key hash must agree with the stored Node spread hash. HashMap-compatible
and ConcurrentHashMap sign-cleared-compatible variants are labeled separately.
`--require-hash` additionally requires cached hashes on both Strings.

Rows contain key/value text and hash evidence, Node offset/klass, next-link
diagnostics, and optional regex labels for each side. Null/non-String/unresolved
values and hash failures are counted, not emitted as invented text. Duplicate
keys and old copies remain. `next` is checked one hop, never traversed recursively;
self-links cannot loop forever. An anomalous next link is labeled but does not
suppress otherwise validated key/value text.

The output does not identify owning maps, certify exact Node classes, or establish
liveness. It does not resolve arbitrary object-valued dictionaries. Each String
payload defaults to a 64 KiB limit, adjustable with `--max-bytes` up to 1 MiB.

## Regex packs and output handling

See [the generic example](../examples/regex-pack.example.json):

```json
{"version":1,"patterns":[{"name":"fatal","regex":"(?i)\\bfatal\\b"}]}
```

`--regex-pack FILE` is supported by `strings`, `dictionaries` and `diff-captures`.
It labels matches without filtering the output. One matching text contributes
one hit per named pattern, regardless of how many times the pattern occurs.
The report records pack SHA-256 and names; it does not embed the expressions.

Packs are at most 64 KiB, with 1–64 unique names and expressions of at most 2,048
bytes each. Names use ASCII letters/digits, `_`, `.` or `-` (1–64 characters).
The Rust regex engine supports Unicode and inline flags, but no lookaround or
backreferences. Compilation and automaton caches are bounded; unsupported or
oversized patterns are refused. Keep private application-specific packs outside
the public repository, for example under ignored `artifacts/`.

New output files use owner-only permissions on Unix and never overwrite an
existing path. Streams on stdout inherit your shell's handling; prefer
`--output` for recovered text. A failed stream may remain on disk without a
completion footer. Neither these commands nor the fixture upload captures.

Not implemented in this increment: a binding registry/auto-reverification,
`dump-json` schema census, timestamps, restart conclusions, mark-word census,
stored-reference drift alerts, or generated Markdown reports.
