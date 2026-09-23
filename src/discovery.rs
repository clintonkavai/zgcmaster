//! Experimental proposals, not automatic class binding or address translation.
use super::*;
use std::collections::BTreeSet;
mod nodes;

const GROUPS_PER_WIDTH: usize = 32;
const MAX_STRING_BYTES: u64 = 4096;
const MAX_PROPOSALS: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum ReferenceModel {
    NonGenLow42,
    GenArmLowAddress,
    GenX86LowAddress,
}
impl ReferenceModel {
    pub(crate) fn parse(name: &str) -> Result<Self> {
        [
            Self::NonGenLow42,
            Self::GenArmLowAddress,
            Self::GenX86LowAddress,
        ]
        .into_iter()
        .find(|m| m.name() == name)
        .ok_or_else(|| invalid("Unknown reference hypothesis; see --help"))
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::NonGenLow42 => "nongen-low42-equals-file-offset",
            Self::GenArmLowAddress => "gen-aarch64-heap-relative-equals-file-offset",
            Self::GenX86LowAddress => "gen-amd64-heap-relative-equals-file-offset",
        }
    }
    pub(crate) fn profile(self, narrow: bool) -> &'static str {
        match (self, narrow) {
            (Self::NonGenLow42, false) => profiles::SUPPORTED[0],
            (Self::NonGenLow42, true) => profiles::SUPPORTED[1],
            (_, false) => profiles::SUPPORTED[2],
            (_, true) => profiles::SUPPORTED[3],
        }
    }
    pub(crate) fn target(self, raw: u64) -> Option<u64> {
        match self {
            Self::NonGenLow42 => {
                if raw >> 46 != 0 || (raw & (7 << 42)).count_ones() != 1 {
                    return None;
                }
                Some(raw & ((1 << 42) - 1))
            }
            Self::GenArmLowAddress | Self::GenX86LowAddress => {
                let arch = if matches!(self, Self::GenArmLowAddress) {
                    "aarch64"
                } else {
                    "amd64"
                };
                let address = gen_address(raw, arch)?;
                if address == 0 {
                    return None;
                }
                Some(address ^ (1u64 << (63 - address.leading_zeros())))
            }
        }
    }
    pub(crate) fn is_null(self, raw: u64) -> bool {
        match self {
            Self::NonGenLow42 => raw == 0,
            Self::GenArmLowAddress | Self::GenX86LowAddress => raw >> 16 == 0,
        }
    }
}

fn read_at(file: &mut File, size: u64, offset: u64, length: u64) -> Result<Option<Vec<u8>>> {
    if length > MAX_STRING_BYTES || offset.checked_add(length).is_none_or(|end| end > size) {
        return Ok(None);
    }
    let mut bytes = vec![0; length as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}
pub(crate) fn mark_ok(bytes: &[u8]) -> bool {
    let mark = word(&bytes[..8]);
    mark & 3 == 1 && mark >> 40 == 0
}
pub(crate) fn java_hash(payload: &[u8], coder: u8) -> u32 {
    let mut hash = 0u32;
    if coder == 0 {
        for &unit in payload {
            hash = hash.wrapping_mul(31).wrapping_add(unit as u32);
        }
    } else {
        for unit in payload.chunks_exact(2) {
            hash = hash.wrapping_mul(31).wrapping_add(word(unit) as u32);
        }
    }
    hash
}
#[derive(Default)]
struct Evidence {
    matches: u64,
    strings: BTreeSet<u64>,
    arrays: BTreeSet<u64>,
    payload_hashes: BTreeSet<[u8; 32]>,
    examples: Vec<Value>,
}

pub fn discover(path: &Path, index: &Index) -> Result<Value> {
    if index.layout.is_some() {
        return Err(invalid(
            "Discovery needs an untyped raw scan, not existing class bindings",
        ));
    }
    let mut file = File::open(path)?;
    if file.metadata()?.len() != index.heap_bytes {
        return Err(invalid("Capture size changed before discovery"));
    }
    let mut proposals = Vec::new();
    let mut reads = 0u64;
    let mut checked = 0u64;
    let mut hash_matches = 0u64;
    let mut groups_considered = 0;
    for narrow in [true, false] {
        let prefix = if narrow { "narrow:" } else { "wide:" };
        let mut groups: Vec<_> = index
            .header_group_stats
            .iter()
            .filter(|(key, s)| key.starts_with(prefix) && !s.periodic && s.sampled_gaps >= 32)
            .collect();
        groups.sort_by(|(ka, a), (kb, b)| b.hits.cmp(&a.hits).then(ka.cmp(kb)));
        groups.truncate(GROUPS_PER_WIDTH);
        groups_considered += groups.len();
        for (key, stats) in groups {
            let klass = number(key.strip_prefix(prefix).unwrap())?;
            let mut offsets = BTreeSet::from([stats.first_offset, stats.last_offset]);
            for gap in &stats.gap_examples {
                offsets.insert(gap.from);
                offsets.insert(gap.to);
            }
            for model in [
                ReferenceModel::NonGenLow42,
                ReferenceModel::GenArmLowAddress,
                ReferenceModel::GenX86LowAddress,
            ] {
                let mut evidence: BTreeMap<u64, Evidence> = BTreeMap::new();
                let mut eligible = 0u64;
                for &offset in &offsets {
                    reads += 1;
                    let Some(string) = read_at(&mut file, index.heap_bytes, offset, 32)? else {
                        continue;
                    };
                    let kw = if narrow { 4 } else { 8 };
                    let hash_at = if narrow { 12 } else { 16 };
                    let coder_at = hash_at + 4;
                    if !mark_ok(&string) || word(&string[8..8 + kw]) != klass {
                        continue;
                    }
                    let cached = word(&string[hash_at..hash_at + 4]) as u32;
                    let coder = string[coder_at];
                    // Require a nonzero cached hash: layout/printability alone is
                    // weak evidence and a zero-filled payload matches too easily.
                    if cached == 0 || coder > 1 || string[coder_at + 1] != 0 {
                        continue;
                    }
                    eligible += 1;
                    checked += 1;
                    let raw = word(&string[24..32]);
                    let Some(target) = model
                        .target(raw)
                        .filter(|t| t.is_multiple_of(8) && *t != offset)
                    else {
                        continue;
                    };
                    reads += 1;
                    let Some(array) = read_at(&mut file, index.heap_bytes, target, 24)? else {
                        continue;
                    };
                    if !mark_ok(&array) {
                        continue;
                    }
                    let array_klass = word(&array[8..8 + kw]);
                    let array_key = format!("{prefix}0x{array_klass:x}");
                    if array_klass == klass
                        || index
                            .header_group_stats
                            .get(&array_key)
                            .is_none_or(|s| s.periodic)
                    {
                        continue;
                    }
                    let lo = 8 + kw;
                    let base = if narrow { 16 } else { 24 };
                    let len = word(&array[lo..lo + 4]);
                    if !(3..=MAX_STRING_BYTES).contains(&len)
                        || (coder == 1 && !len.is_multiple_of(2))
                    {
                        continue;
                    }
                    let Some(end) = aligned(base + len).and_then(|n| target.checked_add(n)) else {
                        continue;
                    };
                    if end > index.heap_bytes || (offset < end && target < offset + 32) {
                        continue;
                    }
                    reads += 1;
                    let Some(payload) = read_at(&mut file, index.heap_bytes, target + base, len)?
                    else {
                        continue;
                    };
                    if java_hash(&payload, coder) != cached {
                        continue;
                    }
                    hash_matches += 1;
                    let e = evidence.entry(array_klass).or_default();
                    e.matches += 1;
                    e.strings.insert(offset);
                    e.arrays.insert(target);
                    e.payload_hashes.insert(Sha256::digest(&payload).into());
                    if e.examples.len() < 4 {
                        e.examples.push(json!({"string_offset":offset,"array_offset":target,"array_bytes":len,"coder":coder,"cached_hash_matches":true}));
                    }
                }
                for (array_klass, e) in evidence {
                    if e.strings.len() < 3 || e.arrays.len() < 3 || e.payload_hashes.len() < 3 {
                        continue;
                    }
                    proposals.push(json!({"profile_assumption":model.profile(narrow),"reference_hypothesis":model.name(),
                        "bindings":{"java.lang.String":format!("0x{klass:x}"),"[B":format!("0x{array_klass:x}")},
                        "confidence":{"level":"supported-hypothesis-not-verified-class-identity","hash_match_fraction":e.matches as f64/eligible as f64,
                            "kind":"sample evidence, not a calibrated probability"},
                        "hash_matches":e.matches,"eligible_samples":eligible,"distinct_arrays":e.arrays.len(),"distinct_payloads":e.payload_hashes.len(),
                        "examples":e.examples,"automatically_applied":false}));
                }
            }
        }
    }
    proposals.sort_by(|a, b| {
        b["hash_matches"]
            .as_u64()
            .cmp(&a["hash_matches"].as_u64())
            .then_with(|| {
                a["reference_hypothesis"]
                    .as_str()
                    .cmp(&b["reference_hypothesis"].as_str())
            })
    });
    let count = proposals.len();
    proposals.truncate(MAX_PROPOSALS);
    let node_discovery = nodes::discover(&mut file, index, &proposals)?;
    // Proposals use additional random reads after scanning; bind their evidence
    // to the same immutable capture rather than silently accepting modifications.
    verify_digest(
        &hash_file(path)?,
        &index.heap_sha256,
        "capture changed during discovery",
    )?;
    Ok(
        json!({"status":if proposals.is_empty(){"no-supported-proposal"}else{"review-required"},"proposals":proposals,
        "hashmap_node_discovery":node_discovery,
        "groups_considered":groups_considered,"structurally_eligible_samples":checked,"hash_matched_pairs":hash_matches,"random_reads":reads,
        "limits":{"groups_per_header_width":GROUPS_PER_WIDTH,"offsets_per_group":34,"max_string_payload_bytes":MAX_STRING_BYTES,"max_proposals":MAX_PROPOSALS},
        "proposals_truncated":count>MAX_PROPOSALS,"group_coverage_truncated":index.groups_truncated,"heap_sha256":index.heap_sha256,
        "caveats":["Assumes Java 21 boot layouts; does not detect JDK version.",
            "Models hypothesize a relationship between uncolored virtual offsets and file offsets. Real ZGC mappings may violate it; failure to find proposals proves nothing.",
            "A custom class can imitate String fields and hash semantics. Proposals are not authoritative class names and never modify the index's bindings.",
            "Requires three distinct arrays/payloads with matching nonzero cached String hashes. Unhashed strings, long strings and periodic groups are not searched.",
            "No raw text is included in the report. Identity-mode references remain unresolved even after manually accepting proposed bindings."]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_and_translation_are_explicit_hypotheses() {
        assert_eq!(java_hash(b"abc", 0), 96354);
        assert_eq!(java_hash(&[b'a', 0, b'b', 0, b'c', 0], 1), 96354);
        assert_eq!(
            ReferenceModel::NonGenLow42.target((1 << 42) | 128),
            Some(128)
        );
        assert_eq!(ReferenceModel::NonGenLow42.target(128), None);
        assert_eq!(ReferenceModel::NonGenLow42.target((3 << 42) | 128), None);
    }
}
