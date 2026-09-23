//! Bounded exact String-set differences with per-capture census. No event/liveness inference.
use super::*;
use crate::raw_strings::{Bindings, Decoded, json_line};
use std::collections::BTreeSet;

pub struct Options {
    pub census: census::Options,
    pub reference_hypothesis: String,
    pub min_len: u64,
    pub require_hash: bool,
    pub max_unique: usize,
    pub max_text_bytes: u64,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        self.census.validate()?;
        discovery::ReferenceModel::parse(&self.reference_hypothesis)?;
        if !(1..=2_000_000).contains(&self.max_unique)
            || !(1..=512 * 1024 * 1024).contains(&self.max_text_bytes)
        {
            return Err(invalid(
                "Corpus bounds: --max-unique 1..2000000; --max-text-bytes 1..536870912 per capture",
            ));
        }
        Ok(())
    }
}
struct Entry {
    first_offset: u64,
    count: u64,
}
struct Snapshot {
    strings: BTreeMap<String, Entry>,
    census: Value,
    coverage: Value,
    profile: String,
    java: String,
    architecture: String,
    identity_mapping: bool,
}
fn snapshot(source: &Path, index: Index, options: &Options) -> Result<Snapshot> {
    let mut reader = Reader::open(source, index)?;
    census::require_indexed(&reader, &["java.lang.String", "[B"])?;
    let layout = reader.index.layout.as_ref().unwrap();
    let ids: BTreeMap<_, _> = layout
        .classes
        .iter()
        .filter(|c| c.name == "java.lang.String" || c.name == "[B")
        .map(|c| (c.name.clone(), c.klass.clone()))
        .collect();
    let expected = profiles::boot(&layout.profile, &ids)?;
    for c in &expected.classes {
        if serde_json::to_value(c)?
            != serde_json::to_value(
                layout
                    .classes
                    .iter()
                    .find(|actual| actual.name == c.name)
                    .unwrap(),
            )?
        {
            return Err(invalid(
                "Corpus diff currently requires the supported boot String/byte[] field layouts",
            ));
        }
    }
    let bindings = Bindings::new(
        &layout.profile,
        &options.reference_hypothesis,
        &ids,
        options.census.max_bytes,
    )?;
    let mut result = Snapshot {
        strings: BTreeMap::new(),
        census: Value::Null,
        coverage: Value::Null,
        profile: layout.profile.clone(),
        java: layout.java.clone(),
        architecture: layout.architecture.clone(),
        identity_mapping: reader.index.identity_mapping,
    };
    let mut counts = BTreeMap::new();
    let mut text_bytes = 0;
    let mut candidates = 0;
    for i in 0..reader.index.objects.len() {
        let object = &reader.index.objects[i];
        if reader.index.class_name(object) != "java.lang.String" {
            continue;
        }
        candidates += 1;
        match bindings.decode_at(&mut reader.file, reader.index.heap_bytes, object.offset)? {
            Decoded::Rejected(reason) => census::bump(&mut counts, reason),
            Decoded::Pair(pair) => {
                if pair.status == "mismatch" {
                    census::bump(&mut counts, "hash-mismatch");
                    continue;
                }
                if options.require_hash && pair.status == "not-cached" {
                    census::bump(&mut counts, "skipped-unhashed");
                    continue;
                }
                let (text, lossy) = pair.text();
                if lossy {
                    census::bump(&mut counts, "skipped-lossy-text");
                    continue;
                }
                if (text.encode_utf16().count() as u64) < options.min_len {
                    census::bump(&mut counts, "skipped-short");
                    continue;
                }
                if let Some(entry) = result.strings.get_mut(&text) {
                    entry.count += 1;
                } else {
                    if result.strings.len() == options.max_unique
                        || text_bytes + text.len() as u64 > options.max_text_bytes
                    {
                        return Err(invalid(
                            "Corpus resource limit exceeded; raise explicit bounds or increase --min-len. No partial diff is reported.",
                        ));
                    }
                    text_bytes += text.len() as u64;
                    result.strings.insert(
                        text,
                        Entry {
                            first_offset: pair.offset,
                            count: 1,
                        },
                    );
                }
                census::bump(&mut counts, pair.status);
            }
        }
    }
    result.coverage = json!({"indexed_string_candidates":candidates,"unique_strings":result.strings.len(),"stored_utf8_bytes":text_bytes,
        "counts":counts,"assumptions":bindings.metadata(),"lossy_utf16_excluded":true});
    result.census = census::collect(&mut reader, options.census)?;
    raw_strings::recheck(
        &census::heap_path(source),
        reader.index.heap_bytes,
        &reader.index.heap_sha256,
    )?;
    Ok(result)
}
fn deltas(before: &Value, after: &Value) -> Value {
    let a = before.as_object().unwrap();
    let b = after.as_object().unwrap();
    let names: BTreeSet<_> = a.keys().chain(b.keys()).collect();
    let mut changes = serde_json::Map::new();
    for name in names {
        let old = a.get(name).and_then(|v| v["count"].as_u64()).unwrap_or(0);
        let new = b.get(name).and_then(|v| v["count"].as_u64()).unwrap_or(0);
        let old_bytes = a
            .get(name)
            .and_then(|v| v["payload_bytes"].as_u64())
            .unwrap_or(0);
        let new_bytes = b
            .get(name)
            .and_then(|v| v["payload_bytes"].as_u64())
            .unwrap_or(0);
        changes.insert(name.clone(),json!({"before_count":old,"after_count":new,"count_delta":new as i64-old as i64,
            "before_payload_bytes":old_bytes,"after_payload_bytes":new_bytes,"payload_bytes_delta":new_bytes as i64-old_bytes as i64}));
    }
    Value::Object(changes)
}
pub fn diff_captures(
    before_source: &Path,
    before_index: &Path,
    after_source: &Path,
    after_index: &Path,
    options: &Options,
    pack: Option<&patterns::Pack>,
    out: &mut dyn Write,
) -> Result<Value> {
    options.validate()?;
    let before = snapshot(before_source, load_index(before_index)?, options)?;
    let after = snapshot(after_source, load_index(after_index)?, options)?;
    if before.profile != after.profile
        || before.java != after.java
        || before.architecture != after.architecture
        || before.identity_mapping != after.identity_mapping
    {
        return Err(invalid(
            "Corpus diff requires matching profile, JDK labels, architecture and identity mode; class IDs may differ",
        ));
    }
    json_line(
        out,
        &json!({"record":"metadata","command":"diff-captures","before_sha256":before.census["heap_sha256"],"after_sha256":after.census["heap_sha256"],
        "reference_hypothesis":options.reference_hypothesis,"min_utf16_units":options.min_len,"require_hash":options.require_hash,
        "regex_pack":pack.map(patterns::Pack::metadata),"semantics":"exact decoded String-set presence changes within bounded, validated candidates; not events or allocations"}),
    )?;
    let mut new_count = 0u64;
    let mut gone_count = 0u64;
    let mut pattern_new = BTreeMap::new();
    let mut pattern_gone = BTreeMap::new();
    for (kind, from, other) in [
        ("new", &after.strings, &before.strings),
        ("gone", &before.strings, &after.strings),
    ] {
        for (text, entry) in from {
            if other.contains_key(text) {
                continue;
            }
            let matched = pack.map_or_else(Vec::new, |p| p.matches(text));
            for name in &matched {
                census::bump(
                    if kind == "new" {
                        &mut pattern_new
                    } else {
                        &mut pattern_gone
                    },
                    name,
                );
            }
            if kind == "new" {
                new_count += 1;
            } else {
                gone_count += 1;
            }
            json_line(
                out,
                &json!({"record":"string-change","change":kind,"text":text,"first_offset":entry.first_offset,
                "candidate_occurrences":entry.count,"regex_matches":matched}),
            )?;
        }
    }
    for (source, snapshot) in [(before_source, &before), (after_source, &after)] {
        raw_strings::recheck(
            &census::heap_path(source),
            snapshot.census["heap_bytes"].as_u64().unwrap(),
            snapshot.census["heap_sha256"].as_str().unwrap(),
        )?;
    }
    let report = json!({"record":"complete","command":"diff-captures","new_strings":new_count,"gone_strings":gone_count,
        "unchanged_strings":after.strings.len() as u64-new_count,"regex_new_strings":pattern_new,"regex_gone_strings":pattern_gone,
        "regex_pack":pack.map(patterns::Pack::metadata),"before_census":before.census,"after_census":after.census,
        "census_deltas":deltas(&before.census["formats"],&after.census["formats"]),
        "before_string_coverage":before.coverage,"after_string_coverage":after.coverage,
        "limits":{"max_unique_per_capture":options.max_unique,"max_text_bytes_per_capture":options.max_text_bytes},
        "caveats":["New/gone means presence in the decoded candidate sets, not proof of restart, incidents, creation or deletion. Stale copies and unresolved references affect coverage.",
            "Different class IDs are allowed, but schema/profile/capture-discipline comparability remains the caller's responsibility. Both capture checksums are revalidated.",
            "Census deltas include candidate copies and over-limit coverage, not deduplicated live payloads. Regex hits count matching changed texts, not occurrences or verified events."]});
    json_line(out, &report)?;
    out.flush()?;
    Ok(report)
}
