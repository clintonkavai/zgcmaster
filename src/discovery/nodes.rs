//! HashMap.Node *prefix-compatible* evidence, not exact class/subclass identity.
use super::*;
use crate::raw_strings::{Bindings, Decoded};

const MAX_ANCHORS: usize = 4;
const MAX_GROUPS: usize = 128;
const MAX_NODES: usize = 16;

pub(super) fn discover(file: &mut File, index: &Index, anchors: &[Value]) -> Result<Value> {
    let mut proposals = Vec::new();
    let mut checked = 0u64;
    let mut reads = 0u64;
    let mut groups_considered = 0;
    let mut groups_truncated = false;
    for anchor in anchors.iter().take(MAX_ANCHORS) {
        let bindings: BTreeMap<String, String> =
            serde_json::from_value(anchor["bindings"].clone())?;
        let string = Bindings::new(
            anchor["profile_assumption"].as_str().unwrap(),
            anchor["reference_hypothesis"].as_str().unwrap(),
            &bindings,
            MAX_STRING_BYTES,
        )?;
        let prefix = if string.narrow { "narrow:" } else { "wide:" };
        let kw = if string.narrow { 4 } else { 8 };
        let key_at = if string.narrow { 16 } else { 24 };
        let node_bytes = key_at + 24;
        let mut groups: Vec<_> = index
            .header_group_stats
            .iter()
            .filter(|(key, s)| key.starts_with(prefix) && !s.periodic && s.sampled_gaps >= 32)
            .collect();
        groups.sort_by(|(ka, a), (kb, b)| b.hits.cmp(&a.hits).then(ka.cmp(kb)));
        groups_truncated |= groups.len() > MAX_GROUPS;
        groups.truncate(MAX_GROUPS);
        groups_considered += groups.len();
        for (group, stats) in groups {
            let klass = number(group.strip_prefix(prefix).unwrap())?;
            if bindings.values().any(|id| number(id).ok() == Some(klass)) {
                continue;
            }
            let mut offsets = BTreeSet::from([stats.first_offset, stats.last_offset]);
            for gap in &stats.gap_examples {
                offsets.insert(gap.from);
                offsets.insert(gap.to);
            }
            let mut keys = BTreeSet::new();
            let mut payloads = BTreeSet::<[u8; 32]>::new();
            let mut matches = 0;
            let mut string_values = 0;
            let mut hashed_values = 0;
            let mut linked = 0;
            let mut negative_hashes = 0;
            let mut examples = Vec::new();
            for &offset in &offsets {
                checked += 1;
                reads += 1;
                let Some(node) = read_at(file, index.heap_bytes, offset, node_bytes as u64)? else {
                    continue;
                };
                if !mark_ok(&node) || word(&node[8..8 + kw]) != klass {
                    continue;
                }
                let hash = word(&node[8 + kw..12 + kw]) as u32;
                let raw_key = word(&node[key_at..key_at + 8]);
                let Some(key) = string.model.target(raw_key).filter(|t| t.is_multiple_of(8)) else {
                    continue;
                };
                // decode_at performs at most three bounded reads. Report a conservative read budget.
                reads += 3;
                let Decoded::Pair(key) = string.decode_at(file, index.heap_bytes, key)? else {
                    continue;
                };
                if key.status != "match" || hash != (key.computed ^ (key.computed >> 16)) {
                    continue;
                }
                if overlaps(offset, node_bytes as u64, key.offset, 32)
                    || overlaps(
                        offset,
                        node_bytes as u64,
                        key.target,
                        if string.narrow { 16 } else { 24 } + key.payload.len() as u64,
                    )
                {
                    continue;
                }
                let next_raw = word(&node[key_at + 16..key_at + 24]);
                let next = if string.model.is_null(next_raw) {
                    None
                } else {
                    let Some(next) = string.model.target(next_raw).filter(|t| {
                        t.is_multiple_of(8)
                            && !overlaps(offset, node_bytes as u64, *t, node_bytes as u64)
                    }) else {
                        continue;
                    };
                    reads += 1;
                    let Some(header) = read_at(file, index.heap_bytes, next, node_bytes as u64)?
                    else {
                        continue;
                    };
                    if !mark_ok(&header) || word(&header[8..8 + kw]) != klass {
                        continue;
                    }
                    Some(next)
                };
                let value_raw = word(&node[key_at + 8..key_at + 16]);
                let mut value_offset = None;
                let mut value_status = "null-or-non-String-or-unresolved";
                if let Some(value) = string
                    .model
                    .target(value_raw)
                    .filter(|t| t.is_multiple_of(8))
                {
                    reads += 3;
                    if let Decoded::Pair(value) = string.decode_at(file, index.heap_bytes, value)?
                        && value.status != "mismatch"
                        && !overlaps(offset, node_bytes as u64, value.offset, 32)
                        && !overlaps(
                            offset,
                            node_bytes as u64,
                            value.target,
                            if string.narrow { 16 } else { 24 } + value.payload.len() as u64,
                        )
                    {
                        value_offset = Some(value.offset);
                        value_status = value.status;
                        string_values += 1;
                        hashed_values += usize::from(
                            value.status == "match" || value.status == "zero-hash-match",
                        );
                    }
                }
                matches += 1;
                negative_hashes += usize::from(hash & 0x8000_0000 != 0);
                linked += usize::from(next.is_some());
                keys.insert(key.offset);
                payloads.insert(Sha256::digest(&key.payload).into());
                if examples.len() < 4 {
                    examples.push(json!({"node_offset":offset,"key_string_offset":key.offset,
                    "value_string_offset":value_offset,"value_hash_status":value_status,"next_node_offset":next,
                    "key_cached_hash_matches":true,"node_spread_hash_matches":true}));
                }
            }
            if matches < 3 || keys.len() < 3 || payloads.len() < 3 {
                continue;
            }
            let mut combined = bindings.clone();
            combined.insert("java.util.HashMap$Node".into(), format!("0x{klass:x}"));
            let mut ambiguity = vec![
                "java.util.HashMap$Node",
                "java.util.LinkedHashMap$Entry",
                "java.util.HashMap$TreeNode",
                "other compatible or imitation classes",
            ];
            if negative_hashes == 0 {
                ambiguity.push(
                    "java.util.concurrent.ConcurrentHashMap$Node (nonnegative spread hashes)",
                );
            }
            proposals.push(json!({"bindings":combined,"profile_assumption":anchor["profile_assumption"],
                "reference_hypothesis":string.model.name(),"layout_family":"java.util.HashMap$Node-compatible-prefix",
                "confidence":{"level":"supported-prefix-hypothesis-not-exact-class-identity","kind":"sample evidence, not a calibrated probability"},
                "sampled_offsets":offsets.len(),"key_hash_and_node_hash_matches":matches,"distinct_keys":keys.len(),
                "distinct_key_payloads":payloads.len(),"string_value_pairs":string_values,"cached_hash_matched_values":hashed_values,
                "same_klass_next_links":linked,"null_next_links":matches-linked,"examples":examples,
                "negative_spread_hash_matches":negative_hashes,
                "automatically_applied":false,"exact_shallow_size_known":false,
                "class_identity_ambiguity":ambiguity}));
        }
    }
    proposals.sort_by(|a, b| {
        b["key_hash_and_node_hash_matches"]
            .as_u64()
            .cmp(&a["key_hash_and_node_hash_matches"].as_u64())
            .then_with(|| a["bindings"].to_string().cmp(&b["bindings"].to_string()))
    });
    let count = proposals.len();
    proposals.truncate(MAX_NODES);
    Ok(
        json!({"status":if proposals.is_empty(){"no-supported-proposal"}else{"review-required"},"proposals":proposals,
        "sampled_node_offsets":checked,"random_read_upper_bound":reads,"groups_considered":groups_considered,
        "limits":{"string_anchors":MAX_ANCHORS,"groups_per_anchor":MAX_GROUPS,"offsets_per_group":34,"max_proposals":MAX_NODES,"max_string_payload_bytes":MAX_STRING_BYTES},
        "anchors_truncated":anchors.len()>MAX_ANCHORS,"groups_truncated":groups_truncated || index.groups_truncated,"proposals_truncated":count>MAX_NODES,
        "caveats":["Depends on the discovered String/byte[] bindings and the same explicit reference-offset hypothesis.",
            "Requires three distinct nonzero hash-confirmed String keys, matching Node spread hashes, and null or same-klass next headers. Values need not be Strings; confirmed String values are counted separately.",
            "Node, LinkedHashMap.Entry and TreeNode share a prefix. A compatible ID is not an exact Node identity; applying the Node template to a subclass underestimates its shallow size.",
            "ConcurrentHashMap.Node can also match when observed spread hashes are nonnegative; it clears the sign bit. Negative spread matches rule out that particular encoding, not all imitation classes.",
            "No map owner, map size, liveness, retained size or complete population is inferred. Periodic and small groups are not searched. No text is included."]}),
    )
}

fn overlaps(a: u64, an: u64, b: u64, bn: u64) -> bool {
    a < b + bn && b < a + an
}
