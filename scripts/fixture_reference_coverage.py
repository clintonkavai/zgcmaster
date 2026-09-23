"""Check where an explicit raw hypothesis agrees with the fixture's captured maps.

Test-only oracle: the raw CLI never receives this mapping information. GC can
permute backing-file pages, so all fixture labels need not be raw-resolvable.
"""
import bisect
import struct


class Coverage:
    def __init__(self, maps, architecture, generational, string_value_offset):
        self.architecture = architecture
        self.generational = generational
        self.string_value_offset = string_value_offset
        self.maps = []
        for line in maps.splitlines():
            columns = line.split()
            if len(columns) >= 6 and "memfd:java_heap" in columns[5]:
                start, end = (int(n, 16) for n in columns[0].split("-"))
                self.maps.append((start, end, int(columns[2], 16)))
        self.maps.sort()
        self.starts = [m[0] for m in self.maps]

    def address(self, raw):
        if not self.generational:
            return raw
        remap = raw >> 12 & 15
        bit = remap ^ 15 if self.architecture == "aarch64" else remap
        if raw >> 16 == 0 or raw & 15 or bit == 0 or bit & (bit - 1):
            return None
        shift = 16 if self.architecture == "aarch64" else 13 + bit.bit_length() - 1
        return raw >> shift

    def mapped(self, raw):
        address = self.address(raw)
        if address is None:
            return None
        i = bisect.bisect_right(self.starts, address) - 1
        if i < 0 or address >= self.maps[i][1]:
            return None
        start, _, offset = self.maps[i]
        return offset + address - start

    def hypothesized(self, raw):
        if not self.generational:
            colors = raw >> 42 & 7
            if raw >> 46 or colors == 0 or colors & (colors - 1):
                return None
            return raw & ((1 << 42) - 1)
        address = self.address(raw)
        return None if not address else address ^ (1 << (address.bit_length() - 1))

    def backing_agrees(self, heap, reference):
        heap.seek(reference["target_offset"] + self.string_value_offset)
        raw = struct.unpack("<Q", heap.read(8))[0]
        mapped = self.mapped(raw)
        return mapped is not None and mapped == self.hypothesized(raw)

    def reference_agrees(self, reference):
        return self.hypothesized(int(reference["raw"], 16)) == reference["target_offset"]
