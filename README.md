# zgcmaster

[![CI](https://github.com/clintonkavai/zgcmaster/actions/workflows/ci.yml/badge.svg)](https://github.com/clintonkavai/zgcmaster/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A command-line explorer for raw Linux ZGC heap backing files. It decodes Java
fields and primitive arrays using a same-process layout sidecar or built-in boot
layouts with explicit capture-specific class bindings, follows
references through captured `/proc/PID/maps`, and exports binary array payloads.
It does not require or generate an HPROF file.

For metadata-free captures, `strings` can stream text under explicitly supplied
boot-class bindings and a reference-offset hypothesis. `verify-bindings` measures
cached-hash agreement on a reproducible sample without exposing text.

This is an experimental reader with a reproducible fixture, not a general Java
heap analyzer. A bare FD copy does not contain all the information needed for
named fields, complete object graphs, GC roots, or retained sizes.

Use only captures you are authorized to inspect. Recovered text can contain
credentials and personal data. Never attach real heap files or decoded output to
public issues. See [Security](SECURITY.md).

## Start here

```sh
git clone https://github.com/clintonkavai/zgcmaster.git
cd zgcmaster
docker compose build cli
docker compose run --rm -T cli --help
```

The CLI needs no running JVM. Put an authorized capture at `captures/heap.raw`,
create `artifacts/`, then run:

```sh
mkdir -p captures artifacts
docker compose run --rm -T cli scan-raw /captures/heap.raw /artifacts/raw.index.json
```

For a native CLI, use an existing Rust 1.88+ toolchain: `cargo install --path . --locked`.
The tested/build-image toolchain is Rust 1.96.0. No host Java is required.

Commands include raw/typed scanning, `summary`, `list`, `show`, `dump`, `strings`,
`verify-bindings`, array `extract`/`carve`, and structural `diff`. Typed operations
require a matching layout or explicit class bindings; a raw scan does not invent
class names. For a known-data example, run the Docker fixture below.

[Contributing](CONTRIBUTING.md) · [Validation](VALIDATION.md) ·
[Correctness boundaries](IMPLEMENTATION-NOTES.md) · [Changelog](CHANGELOG.md)

## Run the reproducible demo

Requirements: Docker with Compose, plus Python 3.10+ for orchestration (standard
library only). Java and Maven run exclusively in containers. Nothing changes the
host Java installation, `JAVA_HOME`, Maven settings, or shell configuration.

```sh
cd zgcmaster
python3 scripts/demo.py
```

The demo builds both images, starts the fixture on `127.0.0.1:18765`, checks Jetty,
JMX and Logback, exercises a traced request, then captures the **actual memfd**.
It checks recovered fields, arrays, UTF-16 strings, references and extracted
binary data against independently generated expected values. Results are written
under `artifacts/`; raw captures are retained under `captures/`. The CLI never
uses `expected.json` to decode objects.

Use `ZGCM_PORT=18766 python3 scripts/demo.py` if the port is occupied. Subsequent
runs can use `--no-build` when sources have not changed. Each run gets a new name.
The fixture remains running after the demo. Stop just this project's fixture:

```sh
docker compose stop fixture
```

## Pinned fixture

| Component | Pin / configuration |
|---|---|
| JVM | Eclipse Temurin **21.0.11+10 LTS**, JDK image pinned by digest |
| GC | Non-generational ZGC by default; generational ZGC via Compose override |
| Heap | Initial 128 MiB, maximum 256 MiB; container limit 768 MiB, two CPUs |
| Layout | Uncompressed object references; uncompressed or compressed class pointers, 8-byte alignment |
| Application | Spring Boot **3.5.3**, executable **WAR**, embedded Jetty |
| Servlet/logging versions | Jetty **12.0.22**, Logback **1.5.18**, fixed by the Boot BOM |
| Instana | Java Trace SDK **1.2.0**; real instrumentation agent optional |
| JMX | Spring MBean `zgcmaster:type=Fixture`, Actuator MBeans, local JVM management |
| Logging | Logback with `trace_id`, `span_id`, and `trace_source` MDC fields |
| Build | Maven **3.9.9**, Rust **1.96.0**; container digests and Cargo lockfile |

The pinned versions are a laboratory compatibility target, not a recommendation
for a new production deployment. Docker chooses native amd64 or arm64 variants
from the pinned multi-platform manifests; the capture records its architecture.

The workload retains 256 linked records, binary byte arrays, signed integer and
long arrays, a gzip payload, strings containing Greek characters, collections,
and a bounded ring of trace events. A fixture-only Java instrumentation agent
reports actual shallow sizes. A small `Unsafe` helper exports class identities
and field offsets; it does not export object contents, object addresses or roots.

## CLI workflow

```sh
mkdir -p captures artifacts
docker compose build fixture cli
docker compose up -d --no-build fixture
curl -fsS -X POST http://127.0.0.1:18765/fixture/request
curl -fsS -X POST http://127.0.0.1:18765/fixture/prepare
docker compose exec -T fixture bash /app/capture.sh sample

docker compose run --rm -T cli scan /captures/sample /artifacts/sample.index.json
docker compose run --rm -T cli summary /artifacts/sample.index.json
docker compose run --rm -T cli list /artifacts/sample.index.json 'Fixture$Sample'
docker compose run --rm -T cli dump /captures/sample /artifacts/sample.index.json 'Fixture$Sample'
```

Take an `offset` from `list` to inspect an object:

```sh
docker compose run --rm -T cli show /captures/sample /artifacts/sample.index.json OFFSET
```

References report the raw virtual address, mapped file offset, and whether an
indexed target exists. Use an array reference's `target_offset` to view its first
64 elements or extract its complete primitive payload:

```sh
docker compose run --rm -T cli extract /captures/sample /artifacts/sample.index.json ARRAY_OFFSET /artifacts/payload.bin
```

Offsets accept decimal or `0x` hexadecimal. Commands produce JSON; `list` and
`dump` produce JSON lines. Pipe them to `jq` for filtering. Existing output files
are refused, including existing index files. Extraction preserves the underlying
little-endian primitive representation, excludes the array header and alignment
padding, and reports the payload SHA-256.

### An existing file without metadata

Put it under `captures/` and run:

```sh
docker compose run --rm -T cli scan-raw /captures/heap.raw /artifacts/raw.index.json
```

This reports byte statistics, separate wide/narrow candidate header groups, and
a compressed-versus-uncompressed header-shape suggestion with confidence.
Confidence is the winning **non-periodic, tracked** vote share, not a calibrated
probability. Fewer than 32 retained votes, a share below 0.8, or any eligible
votes lost to the group cap makes the verdict inconclusive (`confidence: null`).
`retained_vote_share` still reports the descriptive ratio. It does not automatically
select a profile or infer class names, JDK version, GC generation or liveness.
Payload words and old copies can mimic headers. The summary shows 20 groups;
the index retains at most 4,096 and reports truncation. HPROF, gzip and ELF file
signatures are refused.

### Periodic structure filtering

Every retained wide/narrow group records its hit count, detection-eligible count,
first/last file offsets, and spacing statistics in `header_group_stats`.
The scanner samples up to **256 consecutive-hit gaps per group** using a
deterministic reservoir across the full scan (not just a prefix). It reports
sample median, mode, mode fraction, and up to 16 actual gap/offset examples.
It never measures gaps between randomly sampled hits as if they were consecutive.

A group is `periodic: true` when at least 32 gaps were sampled and **strictly
more than 90%** equal the mode. Periodic groups' eligible votes are excluded
before profile detection. Counts reconcile as:

`raw votes = retained votes + excluded periodic votes + untracked votes`

Summary separates `raw_header_groups_structural_metadata_candidates_top20`,
`raw_header_groups_object_like_top20`, and low-sample
`raw_header_groups_unclassified_top20`. The old `raw_header_groups_top20` field
now excludes periodic groups; full unfiltered counts remain in the index.
Group counts need not equal votes: the vote predicate is stricter, and wide and
narrow interpretations can count the same offset. **Do not sum groups into a
unique object count or multiply spacing by count to infer occupied heap bytes.**

Periodic does not prove JVM metadata; contiguous same-sized real objects can
also be periodic. Conversely, non-periodic does not prove objects. This filter
changes raw grouping/detection, never explicitly layout-bound typed objects.
Old indexes without spacing data display an inconclusive verdict and request a
rescan; offset samples cannot be reconstructed from their counts alone.

For typed reading, a sidecar from an unrelated JVM is invalid: class identities
vary between processes. The fixture exports selected classes, not every
Spring/Jetty/agent class. A class-word histogram alone does not associate IDs with
names. Adjacent buckets do not establish that their contents share a class.

### Large captures and streamed files

```sh
# Exact JVM class names; filter before allocating index entries.
docker compose run --rm -T cli scan /captures/sample /artifacts/arrays.json --only '[B,[I,[J'

# No object-vector cap. The index is a summary; objects go to JSONL.
docker compose run --rm -T cli scan /captures/sample /artifacts/stream-summary.json --jsonl /artifacts/objects.jsonl

# No /proc maps required. Never treats a reference value as a file offset.
docker compose run --rm -T cli scan-raw /captures/heap.raw /artifacts/remote.json --identity-mapping
```

Filtering omits reference targets outside the selection; they are labeled
unindexed. Add `java.lang.String,[B` to an existing selection for String decoding
when mappings are available. Streaming memory does not grow with object count,
but output disk usage does. The stream ends in a `record: complete` footer with
the capture hash after checksum verification. Failed/interrupted streams remain
on disk without that footer; do not treat them as complete. Streaming summaries
support `summary` and `diff`, not random-access `show`, `dump`, `extract`, `carve`
or `list`; create a filtered index for those commands.

### Built-in boot layouts without an application sidecar

`profiles` lists supported profile names. `boot-profile PROFILE` prints templates
for `java.lang.String`, `[B`, `[I`, `[J`, `java.util.HashMap$Node`, and
`java.util.ArrayList`. Templates have `UNBOUND` IDs and cannot be scanned as-is.
They cover the supported Java 21 HotSpot layouts, not every possible VM/flag mix.
The integration demo compares every template against the live fixture layout.

Supply known IDs from **this capture**, not the examples or another process:

```sh
docker compose run --rm -T cli scan-raw /captures/heap.raw /artifacts/typed-remote.json \
  --identity-mapping --boot-profile hotspot21-zgc-nongen-uncompressed-le64 \
  --bind '[B=0xYOUR_BYTE_ARRAY_KLASS' --bind 'java.util.HashMap$Node=0xYOUR_NODE_KLASS'

docker compose run --rm -T cli show /captures/heap.raw /artifacts/typed-remote.json OFFSET
```

Replace the non-numeric placeholders with actual hexadecimal IDs. Only bound
classes are scanned. `--layout FILE` alternatively accepts an explicit layout
instead of `--boot-profile`/`--bind`. Raw typed indexes bind the heap hash, but
their caller-supplied class labels are assumptions, not authenticated metadata.
Boot templates use the common amd64/aarch64 field layout and leave the capture's
architecture unspecified. Use an explicit layout to record its architecture and
build; CPU-dependent oop diagnostics remain unknown without that information.

In identity mode, scalar fields, array lengths and primitive payloads are readable;
all non-null references are explicitly unresolved. Consequently a String's backing
array cannot be associated with it reliably and `text_error` is reported instead
of invented text. The separate `strings` command below accepts an explicit mapping
hypothesis; it does not change this identity-mode behavior. A remote file cannot
become reliably named/typed solely by shipping familiar field offsets.

### Experimental binding proposals

```sh
docker compose run --rm -T cli scan-raw /captures/heap.raw /artifacts/discovery.json \
  --identity-mapping --discover-bindings
```

This proposes String/byte[] identities, then searches for **HashMap-node-compatible
prefixes** using those String proposals. It does not automatically bind classes,
resolve identity-mode references or discover ArrayList/int[]/long[] identities.

The bounded pass examines at most 32 non-periodic groups per header width (each
with at least 32 sampled gaps) and 34 sampled offsets per group. Under Java 21
String layouts, it checks headers,
coder, array length/bounds and the nonzero cached String hash against the proposed
array's contents. A reportable proposal needs at least three distinct String
objects, backing arrays and payloads. Payloads are limited to 4,096 bytes; no
recovered text is printed. Hash calculation follows
[Java's String hash contract](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/String.html#hashCode()).

Because maps are absent, proposals explicitly name a **hypothesis**: either
non-generational low-42-bit offsets equal file offsets, or generational AMD64/ARM64
uncolored heap-relative offsets equal file offsets. These relationships need not
hold on an arbitrary capture. The pass rehashes the file after its bounded random
reads and refuses a changed capture. Thus discovery costs an additional sequential
hash pass. Empty results do not mean Strings are absent. Reported match fractions
are sample evidence, not probabilities that the class names are correct; a custom
class could imitate String's representation and hash semantics.

Review `binding_discovery.proposals` before manually supplying its `--bind` values
and `profile_assumption` to a separate typed scan. Multiple proposals can conflict.
`--discover-bindings` cannot combine with `--jsonl`, existing boot bindings or an
explicit layout. The earlier 4,096-group cap still limits discovery coverage.

Node results are in `binding_discovery.hashmap_node_discovery`. At most four String
proposals anchor a search of 128 non-periodic groups each, with up to 34 offsets
per group and 16 final proposals. A proposal needs three distinct nonzero
hash-confirmed String keys/payloads, matching Node spread hashes, and null or
same-klass `next` headers. String values are checked and counted separately;
values of other types do not prevent discovery. Examples contain offsets, not text.
The spread check follows [OpenJDK 21 HashMap](https://raw.githubusercontent.com/openjdk/jdk21u/jdk-21.0.11-ga/src/java.base/share/classes/java/util/HashMap.java).

**Prefix compatibility is not exact class identity.** LinkedHashMap.Entry and
HashMap.TreeNode inherit the Node prefix. ConcurrentHashMap.Node can also match
when observed spread hashes are nonnegative; its spread function clears the sign
bit. Reports retain this ambiguity unless negative matches exclude that encoding.
See [OpenJDK 21 ConcurrentHashMap](https://raw.githubusercontent.com/openjdk/jdk/jdk-21-ga/src/java.base/share/classes/java/util/concurrent/ConcurrentHashMap.java).
Applying the Node template to a subclass underestimates its shallow size. Discovery
does not identify owning maps, reconstruct whole maps, or measure live populations.

### Remote String trawl and sampled verification

These commands read a raw file directly; no index, sidecar or `/proc` maps is
required. Supply **exactly** String and byte[] bindings, a boot profile, and one
named reference hypothesis. Nothing is inferred silently. In the example below,
replace the non-numeric `0xSTRING_ID` and
`0xBYTE_ARRAY_ID` placeholders with reviewed bindings from **your capture**.
Change the profile and reference hypothesis to match its evidence.

```sh
docker compose run --rm -T cli strings /captures/heap.raw \
  --boot-profile hotspot21-zgc-gen-compressedklass-le64 \
  --bind 'java.lang.String=0xSTRING_ID' --bind '[B=0xBYTE_ARRAY_ID' \
  --reference-hypothesis gen-amd64-heap-relative-equals-file-offset \
  --min-len 8 --output /artifacts/strings.jsonl

docker compose run --rm -T cli verify-bindings /captures/heap.raw \
  --boot-profile hotspot21-zgc-gen-compressedklass-le64 \
  --bind 'java.lang.String=0xSTRING_ID' --bind '[B=0xBYTE_ARRAY_ID' \
  --reference-hypothesis gen-amd64-heap-relative-equals-file-offset \
  --samples 1000 --seed 42 --output /artifacts/verify.json
```

Available hypotheses are `nongen-low42-equals-file-offset`,
`gen-amd64-heap-relative-equals-file-offset`, and
`gen-aarch64-heap-relative-equals-file-offset`. They are conditional address models,
not verified JVM configuration. An incompatible generation/profile is refused.

`strings` emits a metadata row, String rows, then a checksummed `record: complete`
footer. Each String has both offsets, raw reference, byte length, coder, UTF-16
unit count, cached/computed hash, `hash_status`, `text`, and `text_lossy`.
Latin-1 and little-endian UTF-16 are decoded. Unpaired surrogates use replacement
characters with `text_lossy: true`; hashes still use the original UTF-16 units.
`--min-len` counts Java UTF-16 units, not bytes or displayed characters (default 1).
Malformed headers, unresolved references and hash mismatches are skipped with
reason counts. Unhashed candidates are emitted as `not-cached` unless
`--require-hash` is set. Zero-hash matches are labeled separately and are weak
evidence. There is no text-based printability filter or deduplication.

The trawl streams without the object-index cap. Its scan buffer is about 1 MiB;
`--max-bytes` bounds each payload (default 65,536; maximum 1,048,576). Over-limit
Strings are counted and skipped, not silently truncated. Output disk use grows
with emitted records. Both commands hash the scan and rehash after random reads;
a changed capture causes failure without a completion footer. This is not an
atomic snapshot mechanism: use an immutable captured file, never a changing live FD.
Interrupted output must not be treated as complete.

`verify-bindings` samples uniformly from the entire stream of aligned, plausible
unlocked/hash String headers, **before** testing fields or references. A deterministic
reservoir makes `--seed` reproducible; `--samples` defaults to 1,000 (maximum 10,000).
If fewer candidates exist, all are checked. The report includes every sampled
offset and failure category, but no text. `confirmation_rate` is matches divided
by compared cached pairs; `confirmed_fraction_of_sample` uses all sampled headers.
Zero denominators produce `null`. A perfect conditional rate does not hide failures
elsewhere in the sample or establish class identity, reference correctness for all
objects, liveness, or absence of hash collisions.

Without `--output`, results go to stdout. With it, a new file is created with
owner-only permissions on Unix and stdout contains a text-free summary. Existing
files are never overwritten. **Recovered text can contain credentials or personal
data**; keep it local and do not commit or upload it. See
[VALIDATION.md](VALIDATION.md) for reproducible fixture checks.

### Array-constrained carving and capture diffs

```sh
docker compose run --rm -T cli carve /captures/sample /artifacts/arrays.json /artifacts/carved
docker compose run --rm -T cli diff /artifacts/before.json /artifacts/after.json
```

Carving revalidates indexed byte-array headers and lengths, then checks **payload
starts** for gzip/JPEG/PNG/GIF/ZIP magic. It exports the entire array payload,
excluding its header/padding, and emits JSONL with offsets and hashes. It does not
scan arbitrary scratch space, identify PEM/JKS from markers, find nested files at
interior offsets, decompress payloads or claim full format validation. These are
structural array candidates, not proof of live arrays. The output directory must
not exist; output is never overwritten. Disk use can be large; overlapping
candidate arrays can export overlapping bytes.

Diff reports structural class-count deltas. It requires equal profiles, Java
build labels, architectures, class schemas and class filters; process-specific
klass rebasing is allowed. Use the same capture discipline yourself: the command
cannot prove equivalent GC timing. Counts are not allocations, retained size or
object identity across snapshots.

### Second fixture and GC pressure

```sh
python3 scripts/demo.py --generational
# Manual alternative:
docker compose -f compose.yaml -f compose.generational.yaml up -d --build fixture
```

The second profile enables both `ZGenerational` and `UseCompressedClassPointers`.
Both demos verify the effective flags, perform bounded allocation pressure and
four explicit GC requests, check that class identities/layouts are unchanged,
then recover and verify the known graph. They use the same modest heap/container
limits. The amd64 generational oop decoder uses color-dependent shifts; aarch64
uses a fixed shift. Class headers use neither oop color encoding.

## Capture consistency and interpretation

`capture.sh` discovers this container's JVM and ZGC memfd, sends `SIGSTOP`, checks
that the process stopped, then copies the raw file and memory mappings. An exit
trap sends `SIGCONT` after errors and interruption. This pauses only the fixture;
there is no privileged host PID namespace or host process attachment. A hard
kill of the capture shell cannot run its trap; restart the fixture if interrupted
that way.

The process can stop in an arbitrary GC phase. Roots and relocation/forwarding
tables are not captured. Old copies can survive in the backing file, some
references can be unresolved or point to reused storage, and successful address
translation does not prove a semantically correct edge. `/fixture/prepare`
touches the known graph to exercise ZGC load barriers, but is not a guarantee
that all heap references are current.

The scanner checks aligned, ordinary unlocked/hash mark words, a known class
identity, and object/array bounds. These checks exclude many false positives but
do not establish object liveness. Locked objects and unknown classes can be
omitted. Counts describe **structural candidates**, never total live objects.
No retained-size or leak-suspect claims are made. Zero-byte counts include zeros
inside valid objects and cannot be treated as free-space measurements.

`show` reports the raw mark word and a structural check score (class identity,
mark shape, bounds), not a GC-consistency probability. `gc_state` is `unknown`;
`stale`/`forwarded` are null. Forwarding-table page detection and stale-copy
identification require missing GC metadata; mark-word inspection alone cannot
provide them. See [the implementation corrections](IMPLEMENTATION-NOTES.md).

Each bundle includes SHA-256 bindings for the raw heap, layout, mappings and
consistency note. `scan` verifies these before committing an index. `show`, `dump`
and `extract` verify the heap and sidecars again and validate selected headers.
Keep capture files immutable during analysis; checksums detect accidental mixing
and modification, not malicious replacement of an entire bundle and its hashes.

Resource limits: 64 GiB input, 1 MiB scan windows plus header overlap, at most
4,096 × 256 sampled gaps (about 16 MiB of pair data plus map/statistics overhead), 2 million
indexed candidates, 2 MiB layout, 16 MiB mapping file and 192 MiB serialized
index. The index stores class descriptions once. The CLI container has a 512 MiB
memory limit and no network. An oversized in-memory index is refused explicitly;
use `--only` or `--jsonl` to stay bounded. JSONL is not a database index.

## Connecting real Instana instrumentation

The default app has SDK span annotations and calls. Without an Instana agent,
those hooks do not collect Instana traces. In that case Logback uses generated
local correlation IDs and labels them `trace_source=local`; status and evidence
never claim an Instana backend was verified.

To use an agent you already operate, supply its actual instrumentation agent JAR
and its SHA-256 through the optional override:

```sh
export INSTANA_AGENT_JAR=/absolute/path/to/agent.jar
export INSTANA_AGENT_SHA256=the_exact_sha256
export INSTANA_AGENT_HOST=host.docker.internal
docker compose -f compose.yaml -f compose.instana.yaml up -d --build fixture
```

The JAR is mounted read-only and its checksum is verified before starting Java.
Follow your agent's supported connection configuration. The public
`instana-javaagent:1.0.0` startup helper is a no-op attachment enabler, not the
tracing implementation; do not substitute it for a real agent. You can also use
Instana's normal host-agent attachment workflow. No Instana account or backend
is created by this project. The default automated demo uses the base Compose
file; test an agent-enabled deployment with the manual CLI workflow.

## Development and checks

All Java build artifacts and Maven caches stay inside Docker. For Rust development,
an existing Rust toolchain can optionally run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
# Includes three scale tests: 2M+ indexing, 2M+ String trawl, sparse 4 GiB+:
cargo test --release --locked -- --include-ignored
```

`docker compose build cli` runs the Rust tests in the pinned Rust image. The demo
is the integration test against an actual JVM and Linux backing file. Unit tests
cover address aliasing, chunk boundaries, invalid array lengths, unsupported
profiles/formats, checksum/schema tampering, field overflow, and overwrite
refusal, color-dependent oop decoding, compressed headers, filtered/streaming
scans, maps-free decoding, carving exclusions and diff compatibility. String and
node checks cover hash validation, failed sample resolutions, bounded reservoirs,
private output files, encoding fidelity, and compatible-prefix ambiguity.
`python3 scripts/check_features.py CAPTURE_NAME` checks the additional CLI paths
against a generated fixture capture. See [validation evidence](VALIDATION.md).
This project uses no `unsafe` Rust.

Useful upstream references:

- [HotSpot Java 21 object layout](https://github.com/openjdk/jdk/blob/jdk-21-ga/src/hotspot/share/oops/oop.hpp)
- [ZGC Linux backing file](https://github.com/openjdk/jdk/blob/jdk-21-ga/src/hotspot/os/linux/gc/z/zPhysicalMemoryBacking_linux.cpp)
- [Instana Java SDK](https://github.com/instana/instana-java-sdk)
- [Spring Boot Jetty configuration](https://docs.spring.io/spring-boot/3.5/how-to/webserver.html)

The next useful contribution is a versioned exporter of broader class metadata
and GC state, accompanied by captures with independently checkable ground truth.

## Contribute and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and test commands.
Bug reports should use synthetic data and include the command, profile, assumptions,
and a minimal reproduction. Security reports use [the private reporting path](SECURITY.md).
Community participation follows [our code of conduct](CODE_OF_CONDUCT.md).

Licensed under [Apache-2.0](LICENSE). Dependencies and optional external agents
retain their own licenses. No real heap captures or Instana agent binaries are
distributed by this repository. This experimental project is not affiliated with
OpenJDK, Eclipse Adoptium, Spring, Jetty, or Instana.
