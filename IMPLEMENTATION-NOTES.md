# Raw-capture correctness boundaries

## Class identity is not an object reference

In [JDK 21's object header](https://github.com/openjdk/jdk/blob/jdk-21-ga/src/hotspot/share/oops/oop.hpp),
the metadata slot is `Klass*` or `narrowKlass`, separate from object references.
Do not apply an oop color mask to it. Native metadata addresses can contain the
proposed mask bits. The regression test constructs two different klass values
that `value & ~(0xf << 42)` would collapse; exact identity keeps them separate.
Outputs preserve `klass_raw` and `klass_identity` (equal for these profiles).

An eight-byte read at header offset 8 with compressed class pointers enabled
includes four bytes of the following field/array length. A histogram of that
combined word can split one class by length or field value. This is one possible
explanation for adjacent buckets, not a diagnosis of any particular capture.
We read exactly four bytes for narrowKlass profiles.

Object references retain their raw encoding. The non-generational diagnostic
`masked_oop` exposes the requested 42-bit-offset hypothesis without using it as a
klass identity or file offset. Actual address translation uses captured mappings.
The diagnostic mask is not universally valid for every non-generational heap size.

## Generational reference encoding

[JDK 21.0.11 zAddress.hpp](https://github.com/openjdk/jdk21u/blob/jdk-21.0.11-ga/src/hotspot/share/gc/z/zAddress.hpp)
defines the remap-bit layout and x86 shifts (13, 14, 15, 16).
[The aarch64 implementation](https://github.com/openjdk/jdk21u/blob/jdk-21.0.11-ga/src/hotspot/cpu/aarch64/gc/z/zAddress_aarch64.inline.hpp)
uses a fixed shift and complemented remap bits. Tests exercise every remap color
for both architectures, including malformed colors and colored nulls. A decoded
address is still not a relocated/live-object guarantee.

## What the memfd does not establish

Boot layouts do not supply process-specific class-name-to-ID bindings. Field
offsets depend on the VM layout configuration, including compressed class pointers.
Bindings are explicit; experimental discovery reports reviewable hypotheses rather
than applying guessed class names. It checks several nonzero cached String hashes
against different candidate backing arrays under named file-offset hypotheses.
That is stronger structural evidence, not authoritative class metadata.
In identity mode references remain
unresolved even if their numeric value happens to equal an indexed file offset.

[ZGC forwarding structures](https://github.com/openjdk/jdk21u/blob/jdk-21.0.11-ga/src/hotspot/share/gc/x/xForwarding.inline.hpp)
are separate collector metadata. This capture includes backing-file bytes, not
a complete native-process core and forwarding state. The reader therefore does
not label byte patterns as forwarding-table pages or assert which copies are
stale. Structural checks, capture hashes and partial-count diffs are available;
liveness and retained sizes are not.

## Implemented scope

- Implemented: filtered indexes, bounded-memory JSONL, maps-free identity mode,
  reusable boot-layout templates with explicit bindings, array-constrained magic
  carving, structural consistency evidence, count diffs, compressed-class plus
  generational fixture, confidence-labeled header-shape detection.
- Added periodicity filtering: whole-stream gap reservoirs, distinct periodic and
  non-periodic reports, excluded/untracked vote accounting, and abstention when
  group truncation leaves eligible hits unclassified. Typed objects are unaffected.
- Added `--discover-bindings`: bounded String/byte[] proposals, cached-hash checks,
  explicit virtual-offset/file-offset assumptions, no automatic binding or text output.
- String trawling and seeded binding verification require explicit profile,
  class IDs, and offset hypotheses. Sample failures remain visible; cached-hash
  agreement is conditional evidence, not proof of class identity or liveness.
- HashMap-node proposals verify String key hashes and spread hashes, report value
  pairs and next links, and retain ambiguity with compatible subclasses/classes.
- Corrected rather than implemented literally: klass color masking (unsafe),
  automatic reliable boot-class naming on every raw file (missing identities),
  forwarding/stale-copy detection from the memfd alone (missing metadata).
- Fixture pin changed from the original 21.0.8+9 to 21.0.11+10, using Docker manifest
  `sha256:dbfd085220ae632a0830166e443747d1ee89e9038d92e3b48c3e5e9d8292b9a7`.
