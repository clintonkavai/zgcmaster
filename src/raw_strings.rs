//! Explicit, hypothesis-bound remote String reading. No identity-mode fallback.
use super::*;
use crate::discovery::{ReferenceModel, java_hash, mark_ok};

pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024;
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_SAMPLES: usize = 10_000;

pub struct Bindings {
    profile: String,
    pub(crate) model: ReferenceModel,
    pub(crate) narrow: bool,
    string_klass: u64,
    array_klass: u64,
    max_bytes: u64,
}
impl Bindings {
    pub fn new(
        profile: &str,
        hypothesis: &str,
        bindings: &BTreeMap<String, String>,
        max_bytes: u64,
    ) -> Result<Self> {
        if bindings.len() != 2
            || !bindings.contains_key("java.lang.String")
            || !bindings.contains_key("[B")
        {
            return Err(invalid(
                "String commands require exactly --bind java.lang.String=ID and --bind '[B=ID'",
            ));
        }
        if !(1..=MAX_BYTES).contains(&max_bytes) {
            return Err(invalid("--max-bytes must be 1..1048576"));
        }
        let layout = profiles::boot(profile, bindings)?;
        validate_layout(&layout)?;
        let narrow = compressed(&layout);
        let model = ReferenceModel::parse(hypothesis)?;
        if model.profile(narrow) != profile {
            return Err(invalid(
                "Reference hypothesis conflicts with boot profile generation",
            ));
        }
        Ok(Self {
            profile: profile.into(),
            model,
            narrow,
            string_klass: number(&bindings["java.lang.String"])?,
            array_klass: number(&bindings["[B"])?,
            max_bytes,
        })
    }
    fn kw(&self) -> usize {
        if self.narrow { 4 } else { 8 }
    }
    pub(crate) fn metadata(&self) -> Value {
        json!({"profile_assumption":self.profile,"reference_hypothesis":self.model.name(),
            "bindings":{"java.lang.String":format!("0x{:x}",self.string_klass),"[B":format!("0x{:x}",self.array_klass)},
            "max_payload_bytes":self.max_bytes,"reference_resolution":"hypothesis-only",
            "gc_liveness":"unknown","class_identity":"caller-assumption"})
    }
    pub(crate) fn decode_at(&self, file: &mut File, size: u64, offset: u64) -> Result<Decoded> {
        let Some(header) = read_at(file, size, offset, 32)? else {
            return Ok(Decoded::Rejected("string-out-of-bounds"));
        };
        self.decode_header(file, size, offset, &header)
    }
    fn decode_header(
        &self,
        file: &mut File,
        size: u64,
        offset: u64,
        header: &[u8],
    ) -> Result<Decoded> {
        let kw = self.kw();
        if !offset.is_multiple_of(8)
            || !mark_ok(header)
            || word(&header[8..8 + kw]) != self.string_klass
        {
            return Ok(Decoded::Rejected("string-header-mismatch"));
        }
        let hash_at = 8 + kw;
        let cached = word(&header[hash_at..hash_at + 4]) as u32;
        let coder = header[hash_at + 4];
        let zero = header[hash_at + 5];
        if coder > 1 || zero > 1 || (zero == 1 && cached != 0) {
            return Ok(Decoded::Rejected("invalid-string-fields"));
        }
        let raw = word(&header[24..32]);
        let Some(target) = self.model.target(raw).filter(|t| t.is_multiple_of(8)) else {
            return Ok(Decoded::Rejected("unresolved-reference"));
        };
        let base = if self.narrow { 16 } else { 24 };
        let Some(array) = read_at(file, size, target, base)? else {
            return Ok(Decoded::Rejected("array-out-of-bounds"));
        };
        if !mark_ok(&array) || word(&array[8..8 + kw]) != self.array_klass {
            return Ok(Decoded::Rejected("array-header-mismatch"));
        }
        let len = word(&array[8 + kw..12 + kw]);
        if len > i32::MAX as u64 || (coder == 1 && !len.is_multiple_of(2)) {
            return Ok(Decoded::Rejected("invalid-array-length"));
        }
        let end = aligned(base + len).and_then(|n| target.checked_add(n));
        if end.is_none_or(|end| end > size || (offset < end && target < offset + 32)) {
            return Ok(Decoded::Rejected("array-extent-or-overlap"));
        }
        if len > self.max_bytes {
            return Ok(Decoded::Rejected("payload-limit"));
        }
        let payload = read_at(file, size, target + base, len)?
            .ok_or_else(|| invalid("Capture changed during String read"))?;
        let computed = java_hash(&payload, coder);
        let status = if cached == 0 && zero == 0 {
            "not-cached"
        } else if cached != computed {
            "mismatch"
        } else if cached == 0 {
            "zero-hash-match"
        } else {
            "match"
        };
        Ok(Decoded::Pair(Pair {
            offset,
            target,
            raw,
            payload,
            coder,
            cached,
            computed,
            status,
        }))
    }
}

pub(crate) enum Decoded {
    Pair(Pair),
    Rejected(&'static str),
}
pub(crate) struct Pair {
    pub(crate) offset: u64,
    pub(crate) target: u64,
    raw: u64,
    pub(crate) payload: Vec<u8>,
    coder: u8,
    cached: u32,
    pub(crate) computed: u32,
    pub(crate) status: &'static str,
}
impl Pair {
    fn units(&self) -> usize {
        self.payload.len() / (1 + self.coder as usize)
    }
    fn evidence(&self) -> Value {
        json!({"string_offset":self.offset,"array_offset":self.target,"reference_raw":format!("0x{:x}",self.raw),
            "array_bytes":self.payload.len(),"utf16_units":self.units(),"coder":self.coder,
            "cached_hash":self.cached,"computed_hash":self.computed,"hash_status":self.status})
    }
    fn text(&self) -> (String, bool) {
        if self.coder == 0 {
            return (self.payload.iter().map(|&b| b as char).collect(), false);
        }
        let mut lossy = false;
        let text = char::decode_utf16(self.payload.chunks_exact(2).map(|b| word(b) as u16))
            .map(|c| {
                c.unwrap_or_else(|_| {
                    lossy = true;
                    char::REPLACEMENT_CHARACTER
                })
            })
            .collect();
        (text, lossy)
    }
}
pub(crate) fn read_at(
    file: &mut File,
    size: u64,
    offset: u64,
    length: u64,
) -> Result<Option<Vec<u8>>> {
    if length > MAX_BYTES || offset.checked_add(length).is_none_or(|end| end > size) {
        return Ok(None);
    }
    let mut bytes = vec![0; length as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

// Constant-memory full scan, independent of the index's two-million-object cap.
// Callback sees every plausible bound String header BEFORE field/reference validation.
fn walk(
    path: &Path,
    bindings: &Bindings,
    mut visit: impl FnMut(u64, &[u8], u64) -> Result<()>,
) -> Result<(u64, String, u64)> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if !file.metadata()?.is_file() || !(32..=MAX_FILE).contains(&size) {
        return Err(invalid("Expected a regular raw file of 32 bytes..64 GiB"));
    }
    let mut buffer = vec![0; CHUNK + 32];
    let mut hash = Sha256::new();
    let mut base = 0;
    let mut count = 0;
    while base < size {
        let n = (size - base).min(buffer.len() as u64) as usize;
        file.seek(SeekFrom::Start(base))?;
        file.read_exact(&mut buffer[..n])?;
        if base == 0
            && (buffer.starts_with(b"JAVA PROFILE")
                || buffer.starts_with(&[0x1f, 0x8b])
                || buffer.starts_with(b"\x7fELF"))
        {
            return Err(invalid("Expected raw ZGC bytes, not HPROF, gzip or ELF"));
        }
        let main = n.min(CHUNK);
        hash.update(&buffer[..main]);
        for pos in (0..main).step_by(8) {
            if pos + 32 > n {
                break;
            }
            let header = &buffer[pos..pos + 32];
            if word(&header[8..8 + bindings.kw()]) == bindings.string_klass && mark_ok(header) {
                count += 1;
                visit(base + pos as u64, header, size)?;
            }
        }
        base += main as u64;
    }
    Ok((size, format!("{:x}", hash.finalize()), count))
}
fn recheck(path: &Path, size: u64, hash: &str) -> Result<()> {
    if std::fs::metadata(path)?.len() != size {
        return Err(invalid("Capture size changed"));
    }
    verify_digest(
        &hash_file(path)?,
        hash,
        "capture changed during String reads",
    )
}
fn json_line(out: &mut dyn Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}
fn bump(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.into()).or_default() += 1;
}

/// Stream decoded String candidates and a checksum-bound completion footer.
pub fn strings(
    path: &Path,
    bindings: &Bindings,
    min_len: u64,
    require_hash: bool,
    out: &mut dyn Write,
) -> Result<Value> {
    let mut file = File::open(path)?;
    let mut counts = BTreeMap::new();
    let mut emitted = 0u64;
    json_line(
        out,
        &json!({"record":"metadata","assumptions":bindings.metadata(),"min_utf16_units":min_len,
        "require_hash":require_hash,"warning":"May contain secrets. Candidates are not proven live objects; require the completion footer."}),
    )?;
    let (size, hash, count) = walk(path, bindings, |offset, header, size| {
        match bindings.decode_header(&mut file, size, offset, header)? {
            Decoded::Rejected(reason) => bump(&mut counts, reason),
            Decoded::Pair(pair) => {
                bump(&mut counts, pair.status);
                if pair.status == "mismatch" {
                    bump(&mut counts, "skipped-hash-mismatch");
                } else if require_hash && pair.status == "not-cached" {
                    bump(&mut counts, "skipped-unhashed");
                } else if (pair.units() as u64) < min_len {
                    bump(&mut counts, "skipped-short");
                } else {
                    let (text, lossy) = pair.text();
                    let mut row = pair.evidence();
                    row["record"] = json!("string");
                    row["text"] = json!(text);
                    row["text_lossy"] = json!(lossy);
                    json_line(out, &row)?;
                    emitted += 1;
                }
            }
        }
        Ok(())
    })?;
    recheck(path, size, &hash)?;
    let report = json!({"record":"complete","heap_sha256":hash,"heap_bytes":size,"header_candidates":count,
        "emitted":emitted,"counts":counts,"assumptions":bindings.metadata(),"min_utf16_units":min_len,"require_hash":require_hash});
    json_line(out, &report)?;
    out.flush()?;
    Ok(report)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        let threshold = n.wrapping_neg() % n;
        loop {
            let x = self.next();
            if x >= threshold {
                return x % n;
            }
        }
    }
}

/// Uniform reservoir over header candidates, not just successfully resolved pairs.
pub fn verify(path: &Path, bindings: &Bindings, samples: usize, seed: u64) -> Result<Value> {
    if !(1..=MAX_SAMPLES).contains(&samples) {
        return Err(invalid("--samples must be 1..10000"));
    }
    let mut selected = Vec::with_capacity(samples);
    let mut seen = 0u64;
    let mut rng = Rng(seed);
    let (size, hash, population) = walk(path, bindings, |offset, _, _| {
        seen += 1;
        if selected.len() < samples {
            selected.push(offset);
        } else {
            let slot = rng.below(seen);
            if slot < samples as u64 {
                selected[slot as usize] = offset;
            }
        }
        Ok(())
    })?;
    selected.sort_unstable();
    let mut file = File::open(path)?;
    let mut counts = BTreeMap::new();
    let mut details = Vec::with_capacity(selected.len());
    for offset in selected {
        match bindings.decode_at(&mut file, size, offset)? {
            Decoded::Rejected(reason) => {
                bump(&mut counts, reason);
                details.push(json!({"string_offset":offset,"status":reason}));
            }
            Decoded::Pair(pair) => {
                bump(&mut counts, pair.status);
                details.push(pair.evidence());
            }
        }
    }
    recheck(path, size, &hash)?;
    let get = |key: &str| counts.get(key).copied().unwrap_or(0);
    let matched = get("match") + get("zero-hash-match");
    let compared = matched + get("mismatch");
    Ok(
        json!({"record":"complete","heap_sha256":hash,"heap_bytes":size,"assumptions":bindings.metadata(),
        "sampling":{"method":"uniform-header-reservoir-splitmix64-rejection-v1","seed":seed,"requested":samples,
            "population":population,"sampled":details.len(),"selection_before_resolution":true},
        "counts":counts,"compared_cached_pairs":compared,"confirmed_cached_pairs":matched,
        "confirmation_rate":if compared>0 { Some(matched as f64/compared as f64) } else { None },
        "confirmed_fraction_of_sample":if !details.is_empty() { Some(matched as f64/details.len() as f64) } else { None },
        "samples":details,"caveats":["Rates are conditional on caller-supplied bindings, profile and offset hypothesis, not probabilities of class identity or liveness.",
            "Population includes every aligned, plausible unlocked/hash header with the bound String klass. Locked and other unsupported mark states are excluded.",
            "Unresolved, malformed, over-limit and unhashed candidates remain in the sample counts, but are excluded from the cached-pair confirmation rate.",
            "Zero hashes are reported separately and provide weak evidence. Hash collisions, stale copies and imitation layouts remain possible. No text is included."]}),
    )
}
