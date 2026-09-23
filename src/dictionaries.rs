//! Streaming Node-prefix key/value candidates, never claims of live or owned maps.
use super::*;
use crate::raw_strings::{Bindings, Decoded, Pair, json_line};

fn overlaps_pair(offset: u64, size: u64, pair: &Pair, narrow: bool) -> bool {
    let overlap = |at, n| offset < at + n && at < offset + size;
    overlap(pair.offset, 32)
        || overlap(
            pair.target,
            (if narrow { 16 } else { 24 }) + pair.payload.len() as u64,
        )
}

pub fn dictionaries(
    path: &Path,
    bindings: &Bindings,
    node_klasses: &[u64],
    require_hash: bool,
    pack: Option<&patterns::Pack>,
    out: &mut dyn Write,
) -> Result<Value> {
    let mut klasses = node_klasses.to_vec();
    klasses.sort_unstable();
    klasses.dedup();
    if klasses.is_empty()
        || klasses.len() > 64
        || klasses.iter().any(|&k| {
            k == 0
                || (bindings.narrow && k > u32::MAX as u64)
                || (!bindings.narrow && !k.is_multiple_of(8))
        })
    {
        return Err(invalid(
            "Supply 1..64 valid --node-klass IDs for this header width",
        ));
    }
    let ka = if bindings.narrow { 16 } else { 24 };
    let size = ka + 24;
    let mut file = File::open(path)?;
    let mut counts = BTreeMap::new();
    let mut emitted = 0u64;
    let mut by_klass = BTreeMap::new();
    json_line(
        out,
        &json!({"record":"metadata","command":"dictionaries","assumptions":bindings.metadata(),
        "node_klasses":klasses.iter().map(|k|format!("0x{k:x}")).collect::<Vec<_>>(),"require_hash":require_hash,
        "regex_pack":pack.map(patterns::Pack::metadata),"scope":"Node-prefix String key/value candidates; owner maps, exact classes and liveness unknown"}),
    )?;
    let (heap_bytes, hash, candidates) = raw_strings::walk_klass(
        path,
        bindings.kw(),
        &klasses,
        size,
        |offset, node, heap_size| {
            let raw_key = word(&node[ka..ka + 8]);
            let raw_value = word(&node[ka + 8..ka + 16]);
            let decode = |file: &mut File, raw| -> Result<Decoded> {
                match bindings.model.target(raw).filter(|t| t.is_multiple_of(8)) {
                    Some(target) => bindings.decode_at(file, heap_size, target),
                    None => Ok(Decoded::Rejected("unresolved-reference")),
                }
            };
            let key = match decode(&mut file, raw_key)? {
                Decoded::Pair(p) => p,
                Decoded::Rejected(reason) => {
                    census::bump(&mut counts, &format!("key-{reason}"));
                    return Ok(());
                }
            };
            if key.status == "mismatch" || overlaps_pair(offset, size as u64, &key, bindings.narrow)
            {
                census::bump(&mut counts, "key-hash-or-overlap-invalid");
                return Ok(());
            }
            let stored = word(&node[8 + bindings.kw()..12 + bindings.kw()]) as u32;
            let spread = key.computed ^ (key.computed >> 16);
            let hash_model = if stored == spread {
                if spread & 0x8000_0000 == 0 {
                    "hashmap-or-concurrent-compatible"
                } else {
                    "hashmap-compatible"
                }
            } else if stored == (spread & 0x7fff_ffff) {
                "concurrent-sign-cleared-compatible"
            } else {
                census::bump(&mut counts, "node-spread-hash-mismatch");
                return Ok(());
            };
            if bindings.model.is_null(raw_value) {
                census::bump(&mut counts, "null-value");
                return Ok(());
            }
            let value = match decode(&mut file, raw_value)? {
                Decoded::Pair(p) => p,
                Decoded::Rejected(reason) => {
                    census::bump(&mut counts, &format!("value-{reason}"));
                    return Ok(());
                }
            };
            if value.status == "mismatch"
                || overlaps_pair(offset, size as u64, &value, bindings.narrow)
            {
                census::bump(&mut counts, "value-hash-or-overlap-invalid");
                return Ok(());
            }
            if require_hash && (key.status == "not-cached" || value.status == "not-cached") {
                census::bump(&mut counts, "skipped-unhashed-pair");
                return Ok(());
            }
            let (key_text, key_lossy) = key.text();
            let (value_text, value_lossy) = value.text();
            let next_raw = word(&node[ka + 16..ka + 24]);
            let next = bindings.model.target(next_raw);
            let next_state = if bindings.model.is_null(next_raw) {
                "null"
            } else if next == Some(offset) {
                "self-reference"
            } else if let Some(next) = next.filter(|t| t.is_multiple_of(8)) {
                match raw_strings::read_at(&mut file, heap_size, next, size as u64)? {
                    Some(b)
                        if discovery::mark_ok(&b)
                            && klasses.contains(&word(&b[8..8 + bindings.kw()])) =>
                    {
                        "bound-node-prefix"
                    }
                    _ => "unresolved-or-other-header",
                }
            } else {
                "unresolved"
            };
            let klass = format!("0x{:x}", word(&node[8..8 + bindings.kw()]));
            let mut row = json!({"record":"dictionary-pair","node_offset":offset,"node_klass":klass,
            "key":key_text,"value":value_text,"key_text_lossy":key_lossy,"value_text_lossy":value_lossy,
            "key_evidence":key.evidence(),"value_evidence":value.evidence(),"node_hash_model":hash_model,
            "next":{"raw":format!("0x{next_raw:x}"),"hypothesized_offset":next,"status":next_state},
            "exact_class_identity":"unknown-node-compatible-prefix","owner_map":null,"live":null});
            if let Some(pack) = pack {
                row["regex_matches"] =
                    json!({"key":pack.matches(&key_text),"value":pack.matches(&value_text)});
            }
            json_line(out, &row)?;
            emitted += 1;
            census::bump(&mut counts, "emitted");
            census::bump(&mut by_klass, &klass);
            Ok(())
        },
    )?;
    raw_strings::recheck(path, heap_bytes, &hash)?;
    let report = json!({"record":"complete","command":"dictionaries","heap_sha256":hash,"heap_bytes":heap_bytes,
        "header_candidates":candidates,"emitted":emitted,"counts":counts,"emitted_by_klass":by_klass,
        "assumptions":bindings.metadata(),"require_hash":require_hash,"regex_pack":pack.map(patterns::Pack::metadata),
        "caveats":["Each node header is visited once, not followed recursively. Next-link anomalies are labeled and do not suppress otherwise validated key/value pairs.",
            "Null/non-String/unresolved values are counted but not emitted. Duplicate keys and stale copies remain; these are not live dictionary populations.",
            "A compatible prefix does not distinguish HashMap.Node, subclasses, ConcurrentHashMap.Node or imitation classes. Node hash variants are reported, not used to certify class identity."]});
    json_line(out, &report)?;
    out.flush()?;
    Ok(report)
}
