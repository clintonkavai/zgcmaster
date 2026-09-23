//! Header-validated byte[] content census. Encoding anomalies do not establish GC tearing.
use super::*;

#[derive(Clone, Copy)]
pub struct Options {
    pub max_bytes: u64,
    pub region_bytes: u64,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_bytes: CHUNK as u64,
            region_bytes: 64 * 1024 * 1024,
        }
    }
}
impl Options {
    pub fn validate(self) -> Result<()> {
        if !(1..=CHUNK as u64).contains(&self.max_bytes) {
            return Err(invalid("--max-bytes must be 1..1048576"));
        }
        if !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&self.region_bytes) {
            return Err(invalid("--region-bytes must be 16 MiB..1 GiB"));
        }
        Ok(())
    }
}
#[derive(Default, Serialize)]
pub(crate) struct Tally {
    pub count: u64,
    pub payload_bytes: u64,
}
pub(crate) fn tally(map: &mut BTreeMap<String, Tally>, name: &str, bytes: u64) {
    let t = map.entry(name.into()).or_default();
    t.count += 1;
    t.payload_bytes += bytes;
}
pub(crate) fn bump(map: &mut BTreeMap<String, u64>, name: &str) {
    *map.entry(name.into()).or_default() += 1;
}

pub(crate) struct Classification {
    pub kind: &'static str,
    pub band: &'static str,
    pub utf8: &'static str,
    pub text_like_anomaly: bool,
}
fn magic(bytes: &[u8]) -> Option<&'static str> {
    analysis::sniff(bytes)
        .map(|s| match s {
            "jpg" => "jpeg",
            "gz" => "gzip",
            other => other,
        })
        .or_else(|| bytes.starts_with(b"%PDF-").then_some("pdf"))
}
pub(crate) fn classify(bytes: &[u8]) -> Classification {
    if bytes.is_empty() {
        return Classification {
            kind: "empty",
            band: "empty",
            utf8: "valid",
            text_like_anomaly: false,
        };
    }
    let decoded = std::str::from_utf8(bytes);
    let utf8 = match &decoded {
        Ok(_) => "valid",
        Err(e) if e.error_len().is_none() => "incomplete-tail",
        Err(_) => "invalid-sequence",
    };
    // Count Unicode scalar values after lossy decoding, explicitly excluding replacement characters.
    // This is a text-likeness heuristic, not an encoding detector for arbitrary binary/Latin-1/UTF-16.
    let text = String::from_utf8_lossy(bytes);
    let total = text.chars().count() as u64;
    let printable = text
        .chars()
        .filter(|&c| {
            c != char::REPLACEMENT_CHARACTER && (!c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        })
        .count() as u64;
    let high = printable * 100 >= total * 95;
    let medium = printable * 100 >= total * 80;
    let band = if high {
        "95-100%"
    } else if medium {
        "80-95%"
    } else if printable * 2 >= total {
        "50-80%"
    } else {
        "0-50%"
    };
    let magic = magic(bytes);
    let json = decoded.as_ref().is_ok_and(|s| {
        let s = s.trim_start();
        (s.starts_with('{') || s.starts_with('[')) && serde_json::from_str::<Value>(s).is_ok()
    });
    let kind = if let Some(magic) = magic {
        magic
    } else if json {
        "json"
    } else if utf8 != "valid" && medium {
        "text-like-invalid-utf8"
    } else if utf8 == "valid" && high {
        "text"
    } else if medium {
        "mixed"
    } else {
        "binary"
    };
    Classification {
        kind,
        band,
        utf8,
        text_like_anomaly: magic.is_none() && utf8 != "valid" && medium,
    }
}

pub(crate) fn require_indexed(reader: &Reader, names: &[&str]) -> Result<()> {
    let layout = reader
        .index
        .layout
        .as_ref()
        .ok_or_else(|| invalid("Typed index required"))?;
    for name in names {
        if !layout.classes.iter().any(|c| &c.name == name)
            || (!reader.index.only.is_empty() && !reader.index.only.iter().any(|n| n == name))
        {
            return Err(invalid(format!(
                "Index must include {name}; rebuild with the needed bindings/--only selection"
            )));
        }
    }
    Ok(())
}
pub(crate) fn heap_path(source: &Path) -> std::path::PathBuf {
    if source.is_dir() {
        source.join("heap.raw")
    } else {
        source.into()
    }
}

pub(crate) fn collect(reader: &mut Reader, options: Options) -> Result<Value> {
    options.validate()?;
    require_indexed(reader, &["[B"])?;
    let mut formats = BTreeMap::new();
    let mut bands = BTreeMap::new();
    let mut encodings = BTreeMap::new();
    let mut regions: BTreeMap<u64, BTreeMap<String, u64>> = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut total = 0u64;
    let mut classified = 0u64;
    let mut full_payloads = 0u64;
    let mut prefix_magic = BTreeMap::new();
    let mut anomalies = 0u64;
    for i in 0..reader.index.objects.len() {
        let object = reader.index.objects[i].clone();
        if reader.index.class_name(&object) != "[B" {
            continue;
        }
        let class = reader.class(&object)?;
        if class.kind != "array" || class.element != "byte" || class.scale != 1 {
            return Err(invalid("[B layout is not a byte array"));
        }
        reader.validate_object(&object, &class)?;
        let length = object
            .length
            .ok_or_else(|| invalid("Byte array has no length"))?;
        total += 1;
        total_bytes += length;
        let region = regions
            .entry(object.offset / options.region_bytes * options.region_bytes)
            .or_default();
        bump(region, "arrays");
        *region.entry("payload_bytes".into()).or_default() += length;
        if length > options.max_bytes {
            // Format signatures can be inspected independently of the full-payload bound.
            // Never perform UTF-8/JSON analysis on a truncated prefix.
            let prefix = reader.bytes(object.offset + class.base, length.min(32))?;
            if let Some(kind) = magic(&prefix) {
                tally(&mut formats, kind, length);
                tally(&mut prefix_magic, kind, length);
                classified += 1;
                bump(region, "classified");
                bump(region, "prefix_only_magic");
            } else {
                tally(&mut formats, "unclassified-over-limit", length);
            }
            bump(region, "over_limit");
            continue;
        }
        let bytes = reader.bytes(object.offset + class.base, length)?;
        let c = classify(&bytes);
        tally(&mut formats, c.kind, length);
        tally(&mut bands, c.band, length);
        bump(&mut encodings, c.utf8);
        bump(region, "classified");
        if c.text_like_anomaly {
            anomalies += 1;
            bump(region, "text_like_utf8_anomalies");
            bump(region, c.utf8);
        }
        classified += 1;
        full_payloads += 1;
    }
    Ok(
        json!({"record":"complete","kind":"byte-array-census","version":1,
        "heap_sha256":reader.index.heap_sha256,"heap_bytes":reader.index.heap_bytes,
        "profile_assumption":reader.index.layout.as_ref().unwrap().profile,
        "indexed_byte_arrays":total,"candidate_payload_bytes":total_bytes,"classified_arrays":classified,
        "formats":formats,"printable_ratio_bands":bands,"utf8_status":encodings,"text_like_utf8_anomalies":anomalies,
        "regions":regions,"policy":{"version":1,"max_payload_bytes":options.max_bytes,"region_bytes":options.region_bytes,
            "text_threshold":0.95,"text_like_threshold":0.80,"printable_ratio":"Unicode scalar values after lossy UTF-8 decode; controls except TAB/CR/LF and replacement characters excluded",
            "json":"whole-payload object/array parse; serde recursion limit applies","region_assignment":"array header start",
            "format_priority":"magic, JSON, invalid-UTF8 text-like, text, mixed, binary; empty separate"},
        "coverage":{"scope":"all indexed [B candidates, not all live arrays","over_limit_arrays":total-full_payloads,
            "full_payload_arrays":full_payloads,"unclassified_arrays":total-classified,
            "prefix_only_magic":prefix_magic,"payloads_deduplicated":false},
        "caveats":["Magic is a format hint, not complete format validation. Counts include stale copies and overlapping candidates; payload-byte totals are not occupied heap size.",
            "Invalid UTF-8 can be binary, Latin-1, UTF-16, deliberate truncation or corruption. Neither an incomplete tail nor an internal invalid sequence proves GC tearing or quantifies actual torn objects.",
            "UTF-8/JSON analysis is only performed for complete payloads within the configured bound. Longer arrays receive a payload-start magic hint from at most 32 bytes or remain explicitly unclassified; no truncated-prefix encoding analysis is performed."]}),
    )
}
pub fn census(source: &Path, index: Index, options: Options) -> Result<Value> {
    options.validate()?;
    let mut reader = Reader::open(source, index)?;
    let report = collect(&mut reader, options)?;
    raw_strings::recheck(
        &heap_path(source),
        reader.index.heap_bytes,
        &reader.index.heap_sha256,
    )?;
    Ok(report)
}
