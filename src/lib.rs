use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub mod analysis;
pub mod discovery;
pub mod profiles;
pub mod raw_strings;
#[cfg(test)]
mod regression_tests;
pub mod spacing;

pub const PROFILE: &str = "hotspot21-zgc-nongen-uncompressed-le64";
const CHUNK: usize = 1024 * 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_OBJECTS: usize = 2_000_000;
const MAX_INDEX_BYTES: u64 = 192 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::Invalid(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub r#type: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Class {
    pub name: String,
    pub klass: String,
    pub kind: String,
    pub size: u64,
    pub fields: Vec<Field>,
    #[serde(default)]
    pub element: String,
    #[serde(default)]
    pub base: u64,
    #[serde(default)]
    pub scale: u64,
    #[serde(default)]
    pub length_offset: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layout {
    pub version: u32,
    pub profile: String,
    pub java: String,
    pub architecture: String,
    pub classes: Vec<Class>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub offset: u64,
    pub size: u64,
    pub class_id: usize,
    pub length: Option<u64>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    pub mode: String,
    pub heap_sha256: String,
    pub heap_bytes: u64,
    pub zero_bytes: u64,
    pub layout_sha256: Option<String>,
    pub maps_sha256: Option<String>,
    pub layout: Option<Layout>,
    pub mappings: Vec<Mapping>,
    pub objects: Vec<Object>,
    pub raw_header_groups: BTreeMap<String, u64>,
    #[serde(default)]
    pub header_group_stats: BTreeMap<String, spacing::GroupStats>,
    pub groups_truncated: bool,
    pub rejected_headers: u64,
    pub limitations: Vec<String>,
    #[serde(default)]
    pub identity_mapping: bool,
    #[serde(default)]
    pub only: Vec<String>,
    #[serde(default)]
    pub streamed: bool,
    #[serde(default)]
    pub class_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub detection: Value,
    #[serde(default)]
    pub binding_discovery: Value,
}

#[derive(Default)]
pub struct ScanOptions {
    pub only: Vec<String>,
    pub identity_mapping: bool,
    pub layout: Option<Layout>,
    pub discover_bindings: bool,
}
fn compressed(layout: &Layout) -> bool {
    layout.profile.contains("-compressedklass-")
}
fn klass_width(layout: &Layout) -> usize {
    if compressed(layout) { 4 } else { 8 }
}
fn length_offset(layout: &Layout) -> usize {
    if compressed(layout) { 12 } else { 16 }
}
fn generational(layout: &Layout) -> bool {
    layout.profile.contains("-gen-")
}
// JDK21 zAddress.hpp: x86 shift follows the one-hot remap nibble;
// AArch64 has complemented remap bits and a fixed 16-bit shift.
fn gen_address(raw: u64, architecture: &str) -> Option<u64> {
    if raw >> 16 == 0 {
        return Some(0);
    }
    if raw & 0xf != 0 {
        return None;
    }
    let remap = (raw >> 12) & 0xf;
    let shift = match architecture {
        "aarch64" if (remap ^ 0xf).is_power_of_two() => 16,
        "amd64" if remap.is_power_of_two() => 13 + remap.trailing_zeros(),
        _ => return None,
    };
    let address = raw >> shift;
    address.is_multiple_of(8).then_some(address)
}

impl Index {
    pub fn class_name(&self, object: &Object) -> &str {
        self.layout
            .as_ref()
            .and_then(|l| l.classes.get(object.class_id))
            .map_or("unknown", |c| c.name.as_str())
    }
    pub fn object_view(&self, object: &Object) -> Value {
        json!({"offset": object.offset, "size": object.size,
            "class": self.class_name(object), "length": object.length,
            "klass_raw": self.layout.as_ref().map(|l| &l.classes[object.class_id].klass),
            "klass_identity": self.layout.as_ref().map(|l| &l.classes[object.class_id].klass),
            "identity_kind": "native-klass-or-narrowKlass-not-colored-oop",
            "gc_state": "unknown", "forwarded": null, "stale": null})
    }
}

pub fn number(s: &str) -> Result<u64> {
    let result = match s.strip_prefix("0x") {
        Some(s) => u64::from_str_radix(s, 16),
        None => s.parse(),
    };
    result.map_err(|_| invalid(format!("Invalid unsigned offset: {s}")))
}
fn word(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(value)
}
fn width(kind: &str) -> Result<u64> {
    match kind {
        "boolean" | "byte" => Ok(1),
        "char" | "short" => Ok(2),
        "int" | "float" => Ok(4),
        "long" | "double" | "reference" => Ok(8),
        _ => Err(invalid(format!("Unsupported field type: {kind}"))),
    }
}
fn aligned(n: u64) -> Option<u64> {
    n.checked_add(7).map(|n| n & !7)
}
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid(format!("{} exceeds {limit} bytes", path.display())));
    }
    Ok(bytes)
}
pub fn hash_file(path: &Path) -> Result<String> {
    let mut reader = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; CHUNK];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn validate_layout(layout: &Layout) -> Result<()> {
    if layout.version != 1
        || !profiles::SUPPORTED.contains(&layout.profile.as_str())
        || !layout.java.starts_with("21.")
        || !(["amd64", "aarch64"].contains(&layout.architecture.as_str())
            || (layout.architecture == "unspecified" && layout.java == "21.0-template"))
    {
        return Err(invalid(
            "Unsupported layout: requires a supported Java 21 ZGC profile, little-endian amd64/aarch64",
        ));
    }
    if layout.classes.is_empty() || layout.classes.len() > 2048 {
        return Err(invalid("Class count must be 1..2048"));
    }
    let mut seen = HashMap::new();
    for class in &layout.classes {
        let klass = number(&class.klass)?;
        if klass == 0
            || (compressed(layout) && klass > u32::MAX as u64)
            || (!compressed(layout) && klass % 8 != 0)
            || seen.insert(klass, ()).is_some()
        {
            return Err(invalid("Invalid or duplicate class identity"));
        }
        if class.name.len() > 1024 || class.fields.len() > 512 {
            return Err(invalid("Class description exceeds limits"));
        }
        match class.kind.as_str() {
            "array" => {
                if class.length_offset != length_offset(layout) as u64
                    || class.base != if compressed(layout) { 16 } else { 24 }
                    || class.scale != width(&class.element)?
                    || !class.fields.is_empty()
                {
                    return Err(invalid("Unsupported array layout"));
                }
            }
            "instance" => {
                if class.size < 16 || class.size > CHUNK as u64 || class.size % 8 != 0 {
                    return Err(invalid("Invalid instance size"));
                }
                for field in &class.fields {
                    if field.name.len() > 1024
                        || field.offset < if compressed(layout) { 12 } else { 16 }
                        || field
                            .offset
                            .checked_add(width(&field.r#type)?)
                            .is_none_or(|end| end > class.size)
                    {
                        return Err(invalid("Field extends outside instance"));
                    }
                }
            }
            _ => return Err(invalid("Unknown class kind")),
        }
    }
    Ok(())
}
pub fn parse_maps(text: &str, file_size: u64) -> Result<Vec<Mapping>> {
    let mut maps = Vec::new();
    for line in text
        .lines()
        .filter(|line| line.contains("/memfd:java_heap"))
    {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 6 || !columns[1].starts_with('r') {
            continue;
        }
        let (start, end) = columns[0]
            .split_once('-')
            .ok_or_else(|| invalid("Bad mapping range"))?;
        let hex = |s: &str| u64::from_str_radix(s, 16).map_err(|_| invalid("Bad mapping address"));
        let mapping = Mapping {
            start: hex(start)?,
            end: hex(end)?,
            offset: hex(columns[2])?,
        };
        if mapping.end <= mapping.start
            || mapping
                .offset
                .checked_add(mapping.end - mapping.start)
                .is_none_or(|end| end > file_size)
        {
            return Err(invalid("Mapping outside backing file"));
        }
        maps.push(mapping);
        if maps.len() > 65_536 {
            return Err(invalid("Too many memory mappings"));
        }
    }
    if maps.is_empty() {
        return Err(invalid("No readable ZGC memfd mappings"));
    }
    maps.sort_by_key(|map| map.start);
    if maps.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(invalid("Overlapping virtual mappings"));
    }
    Ok(maps)
}
fn translate(maps: &[Mapping], address: u64) -> Option<u64> {
    let i = maps
        .partition_point(|m| m.start <= address)
        .checked_sub(1)?;
    let map = &maps[i];
    (address < map.end).then(|| map.offset + address - map.start)
}
fn checksums(bundle: &Path) -> Result<BTreeMap<String, String>> {
    let bytes = read_bounded(&bundle.join("SHA256SUMS"), 8192)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("Bad checksum file"))?;
    let mut sums = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let hash = fields.next().ok_or_else(|| invalid("Missing digest"))?;
        let name = fields
            .next()
            .ok_or_else(|| invalid("Missing checksum filename"))?;
        if fields.next().is_some()
            || hash.len() != 64
            || !hash.bytes().all(|c| c.is_ascii_hexdigit())
            || ![
                "heap.raw",
                "layout.json",
                "maps.txt",
                "expected.json",
                "consistency.txt",
            ]
            .contains(&name)
            || sums.insert(name.to_owned(), hash.to_lowercase()).is_some()
        {
            return Err(invalid("Invalid checksum entry"));
        }
    }
    for name in ["heap.raw", "layout.json", "maps.txt", "consistency.txt"] {
        if !sums.contains_key(name) {
            return Err(invalid(format!("Missing {name} checksum")));
        }
    }
    Ok(sums)
}
fn verify_digest(actual: &str, expected: &str, name: &str) -> Result<()> {
    if actual != expected {
        return Err(invalid(format!("Checksum mismatch: {name}")));
    }
    Ok(())
}
pub fn scan_bundle(bundle: &Path) -> Result<Index> {
    scan_bundle_with(bundle, &ScanOptions::default(), None)
}
pub fn scan_bundle_with(
    bundle: &Path,
    options: &ScanOptions,
    stream: Option<&mut dyn Write>,
) -> Result<Index> {
    if options.discover_bindings {
        return Err(invalid("--discover-bindings is only for untyped scan-raw"));
    }
    let sums = checksums(bundle)?;
    let layout_bytes = read_bounded(&bundle.join("layout.json"), 2 * CHUNK as u64)?;
    let maps_bytes = read_bounded(&bundle.join("maps.txt"), 16 * CHUNK as u64)?;
    let consistency = read_bounded(&bundle.join("consistency.txt"), 8192)?;
    for (name, bytes) in [
        ("layout.json", &layout_bytes),
        ("maps.txt", &maps_bytes),
        ("consistency.txt", &consistency),
    ] {
        verify_digest(&format!("{:x}", Sha256::digest(bytes)), &sums[name], name)?;
    }
    let layout: Layout = serde_json::from_slice(&layout_bytes)?;
    validate_layout(&layout)?;
    let heap = bundle.join("heap.raw");
    let maps = parse_maps(
        std::str::from_utf8(&maps_bytes).map_err(|_| invalid("Invalid maps UTF-8"))?,
        heap.metadata()?.len(),
    )?;
    let mut index = scan_with(
        &heap,
        Some(layout),
        maps,
        options,
        stream,
        Some(&sums["heap.raw"]),
    )?;
    verify_digest(&index.heap_sha256, &sums["heap.raw"], "heap.raw")?;
    index.layout_sha256 = Some(sums["layout.json"].clone());
    index.maps_sha256 = Some(sums["maps.txt"].clone());
    Ok(index)
}
pub fn scan_raw(path: &Path) -> Result<Index> {
    scan(path, None, Vec::new())
}
pub fn scan_raw_with(
    path: &Path,
    options: &ScanOptions,
    stream: Option<&mut dyn Write>,
) -> Result<Index> {
    if options.discover_bindings && (options.layout.is_some() || stream.is_some()) {
        return Err(invalid(
            "--discover-bindings cannot combine with a layout, boot bindings or --jsonl",
        ));
    }
    if options.layout.is_some() && !options.identity_mapping {
        return Err(invalid(
            "Raw typed scans require --identity-mapping; no virtual mappings are available",
        ));
    }
    let mut index = scan_with(
        path,
        options.layout.clone(),
        Vec::new(),
        options,
        stream,
        None,
    )?;
    if options.discover_bindings {
        index.binding_discovery = discovery::discover(path, &index)?;
    }
    Ok(index)
}

fn scan(path: &Path, layout: Option<Layout>, mappings: Vec<Mapping>) -> Result<Index> {
    scan_with(path, layout, mappings, &ScanOptions::default(), None, None)
}
fn scan_with(
    path: &Path,
    layout: Option<Layout>,
    mappings: Vec<Mapping>,
    options: &ScanOptions,
    mut stream: Option<&mut dyn Write>,
    expected_hash: Option<&str>,
) -> Result<Index> {
    if let Some(layout) = &layout {
        validate_layout(layout)?;
    }
    if !options.only.is_empty() && layout.is_none() {
        return Err(invalid("--only needs a layout or bound boot profile"));
    }
    if let Some(layout) = &layout {
        for name in &options.only {
            if !layout.classes.iter().any(|c| &c.name == name) {
                return Err(invalid(format!("Unknown --only class: {name}")));
            }
        }
    }
    let kw = layout.as_ref().map_or(8, klass_width);
    let lo = layout.as_ref().map_or(16, length_offset);
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if !(24..=MAX_FILE).contains(&size) {
        return Err(invalid("Heap size must be 24 bytes..64 GiB"));
    }
    let mut signature = [0; 18];
    file.read_exact(&mut signature)?;
    if signature.starts_with(b"JAVA PROFILE")
        || signature.starts_with(&[0x1f, 0x8b])
        || signature.starts_with(b"\x7fELF")
    {
        return Err(invalid(
            "Expected raw ZGC backing bytes, received HPROF, gzip or ELF",
        ));
    }
    let classes: HashMap<u64, (usize, &Class)> = layout
        .as_ref()
        .map(|l| {
            l.classes
                .iter()
                .enumerate()
                .map(|(id, c)| Ok((number(&c.klass)?, (id, c))))
                .collect::<Result<HashMap<_, _>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut objects = Vec::new();
    let mut spacing = spacing::Collector::default();
    let mut rejected = 0;
    let mut zeros = 0;
    let mut class_counts = BTreeMap::new();
    let mut hash = Sha256::new();
    let mut buffer = vec![0; CHUNK + 24];
    let mut base = 0;
    while base < size {
        let n = (size - base).min(buffer.len() as u64) as usize;
        file.seek(SeekFrom::Start(base))?;
        file.read_exact(&mut buffer[..n])?;
        let main = n.min(CHUNK);
        hash.update(&buffer[..main]);
        zeros += buffer[..main].iter().filter(|&&b| b == 0).count() as u64;
        for pos in (0..main).step_by(8) {
            if pos + 16 > n {
                break;
            }
            let offset = base + pos as u64;
            let mark = word(&buffer[pos..pos + 8]);
            let full = word(&buffer[pos + 8..pos + 16]);
            let low = full & 0xffff_ffff;
            let plausible = mark & 3 == 1 && mark >> 40 == 0;
            // These are competing header-shape hypotheses, not calibrated probabilities.
            if plausible {
                if (1u64 << 32..1u64 << 48).contains(&full) && full.is_multiple_of(8) {
                    spacing.observe(spacing::Kind::Wide, full, offset, full >= 1 << 40);
                }
                if (0x1000..0x4000_0000).contains(&low) {
                    spacing.observe(spacing::Kind::Narrow, low, offset, (full >> 32) < (1 << 15));
                }
            }
            let klass = word(&buffer[pos + 8..pos + 8 + kw]);
            if let Some((class_id, class)) = classes.get(&klass) {
                if !options.only.is_empty() && !options.only.contains(&class.name) {
                    continue;
                }
                // Exclude class metadata pointers embedded in other objects. We
                // accept ordinary unlocked/hash headers and mark other shapes
                // unsupported; this intentionally omits locked object candidates.
                if !plausible || (class.kind == "array" && pos + lo + 4 > n) {
                    rejected += 1;
                    continue;
                }
                let length = (class.kind == "array").then(|| word(&buffer[pos + lo..pos + lo + 4]));
                let object_size = match length {
                    Some(len) if len <= i32::MAX as u64 => len
                        .checked_mul(class.scale)
                        .and_then(|n| n.checked_add(class.base))
                        .and_then(aligned),
                    Some(_) => None,
                    None => Some(class.size),
                };
                let Some(object_size) =
                    object_size.filter(|&n| offset.checked_add(n).is_some_and(|end| end <= size))
                else {
                    rejected += 1;
                    continue;
                };
                if stream.is_none() && objects.len() >= MAX_OBJECTS {
                    return Err(invalid(
                        "2,000,000 object index limit reached; use --only CLASS,... or --jsonl FILE for a bounded-memory stream",
                    ));
                }
                let object = Object {
                    offset,
                    size: object_size,
                    class_id: *class_id,
                    length,
                };
                *class_counts.entry(class.name.clone()).or_insert(0u64) += 1;
                if let Some(writer) = stream.as_deref_mut() {
                    serde_json::to_writer(
                        &mut *writer,
                        &json!({"record":"object", "offset":offset,
                        "size": object_size, "length":length, "class":class.name, "klass_raw":class.klass,
                        "klass_identity":class.klass, "mark_raw":format!("0x{mark:x}"),
                        "gc_state":"unknown", "consistency": {"scope":"header-and-bounds-only", "checks_passed":3,"checks_total":3}}),
                    )?;
                    writer.write_all(b"\n")?;
                } else {
                    objects.push(object);
                }
            }
        }
        base += main as u64;
    }
    let typed = layout.is_some();
    let spacing = spacing.finish();
    let groups = spacing
        .stats
        .iter()
        .map(|(key, stats)| (key.clone(), stats.hits))
        .collect();
    let index = Index {
        version: 1, mode: if typed { "layout-assisted" } else { "raw-candidates" }.into(),
        heap_sha256: format!("{:x}", hash.finalize()), heap_bytes: size, zero_bytes: zeros,
        layout_sha256: None, maps_sha256: None, layout, mappings, objects,
        raw_header_groups: groups, header_group_stats: spacing.stats, groups_truncated: spacing.truncated, rejected_headers: rejected,
        identity_mapping: options.identity_mapping, only: options.only.clone(), streamed: stream.is_some(), class_counts,
        detection: spacing.detection,
        binding_discovery: Value::Null,
        limitations: vec![
            "Objects are structural candidates, not proof of liveness; roots are absent.".into(),
            "Only ordinary unlocked/hash mark words are scanned; locked objects can be omitted.".into(),
            "Unknown classes are not enumerated in layout-assisted mode; counts are partial.".into(),
            "A process stop freezes an arbitrary GC phase; stale copies and unresolved references may remain.".into(),
            "Header-shape detection is heuristic, not a profile selection or class-name identification.".into(),
            "Periodicity is sampled spacing evidence, not proof of metadata; filtering can exclude regularly allocated real objects.".into(),
            "Forwarding tables and ZGC liveness metadata are not available in a heap backing-file capture; GC state is unknown.".into(),
            "Class metadata identities are not colored oops and must not be color-masked.".into(),
        ],
    };
    if let Some(expected) = expected_hash {
        verify_digest(&index.heap_sha256, expected, "heap.raw")?;
    }
    if let Some(writer) = stream {
        serde_json::to_writer(
            &mut *writer,
            &json!({"record":"complete", "summary":summary(&index)}),
        )?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(index)
}
pub fn write_index(path: &Path, index: &Index) -> Result<()> {
    // Exclusive creation prevents replacing a previous analysis or input capture.
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = io::BufWriter::new(file);
    serde_json::to_writer(&mut writer, index)?;
    writer.flush()?;
    Ok(())
}
pub fn load_index(path: &Path) -> Result<Index> {
    let index: Index = serde_json::from_slice(&read_bounded(path, MAX_INDEX_BYTES)?)?;
    if index.version != 1
        || index.heap_bytes > MAX_FILE
        || index.objects.len() > MAX_OBJECTS
        || index.mappings.len() > 65_536
        || index.raw_header_groups.len() > 4096
        || index.header_group_stats.len() > spacing::MAX_GROUPS
        || index.only.len() > 2048
        || index.class_counts.len() > 2048
        || index
            .class_counts
            .values()
            .try_fold(0u64, |sum, n| sum.checked_add(*n))
            .is_none_or(|n| n > index.heap_bytes / 8)
        || (index.streamed && !index.objects.is_empty())
    {
        return Err(invalid("Invalid index version or resource limits"));
    }
    if !index.header_group_stats.is_empty()
        && (index.header_group_stats.len() != index.raw_header_groups.len()
            || index.header_group_stats.iter().any(|(key, stats)| {
                index.raw_header_groups.get(key) != Some(&stats.hits)
                    || !spacing::validate(stats, index.heap_bytes)
            }))
    {
        return Err(invalid("Invalid header spacing statistics"));
    }
    if let Some(layout) = &index.layout {
        validate_layout(layout)?;
    }
    if index
        .objects
        .windows(2)
        .any(|pair| pair[0].offset >= pair[1].offset)
    {
        return Err(invalid("Index offsets must be strictly increasing"));
    }
    for object in &index.objects {
        if index
            .layout
            .as_ref()
            .is_none_or(|l| object.class_id >= l.classes.len())
        {
            return Err(invalid("Index class ID outside layout"));
        }
        if object.offset % 8 != 0
            || object
                .offset
                .checked_add(object.size)
                .is_none_or(|end| end > index.heap_bytes)
        {
            return Err(invalid("Index object outside heap"));
        }
    }
    if !index.streamed && !index.class_counts.is_empty() {
        let mut actual = BTreeMap::new();
        for object in &index.objects {
            *actual
                .entry(index.class_name(object).to_string())
                .or_insert(0u64) += 1;
        }
        if actual != index.class_counts {
            return Err(invalid("Class counts differ from indexed objects"));
        }
    }
    Ok(index)
}
pub fn summary(index: &Index) -> Value {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for object in &index.objects {
        *counts.entry(index.class_name(object)).or_default() += 1;
    }
    let mut top: Vec<_> = index
        .raw_header_groups
        .iter()
        .filter(|(key, _)| {
            index
                .header_group_stats
                .get(*key)
                .is_none_or(|s| !s.periodic)
        })
        .collect();
    top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    top.truncate(20);
    let counts: BTreeMap<&str, u64> = if index.class_counts.is_empty() {
        counts
    } else {
        index
            .class_counts
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect()
    };
    let (object_like, periodic, unclassified) = spacing::summary_groups(&index.header_group_stats);
    let mut detection = index.detection.clone();
    if detection.get("method").is_none() {
        detection = json!({"suggestion":"inconclusive", "confidence":null,
            "abstention_reason":"legacy index has no spacing analysis; rescan the capture", "legacy_unfiltered_detection":detection});
    }
    json!({"mode": index.mode, "heap_bytes": index.heap_bytes, "zero_bytes": index.zero_bytes,
        "heap_sha256": index.heap_sha256, "candidate_objects": counts.values().sum::<u64>(), "indexed_objects":index.objects.len(), "class_counts": counts,
        "identity_mapping":index.identity_mapping, "only":index.only, "streamed":index.streamed, "profile_detection":detection,
        "raw_header_groups_top20": top, "groups_truncated": index.groups_truncated,
        "raw_header_groups_object_like_top20":object_like,
        "raw_header_groups_structural_metadata_candidates_top20":periodic,
        "raw_header_groups_unclassified_top20":unclassified,
        "header_group_labels_note":"Object-like means non-periodic, not verified objects. Structural/metadata candidates means periodic, not proven metadata. Low-sample groups remain unclassified.",
        "binding_discovery":index.binding_discovery,
        "rejected_headers": index.rejected_headers, "limitations": index.limitations})
}

pub struct Reader {
    file: File,
    pub index: Index,
}
impl Reader {
    pub fn open(bundle: &Path, index: Index) -> Result<Self> {
        if index.streamed {
            return Err(invalid(
                "Streaming summary has no random-access objects; make a filtered index with --only",
            ));
        }
        if bundle.is_file() {
            if !index.identity_mapping || index.layout.is_none() || index.layout_sha256.is_some() {
                return Err(invalid(
                    "Raw decoding requires a typed --identity-mapping index",
                ));
            }
            validate_layout(index.layout.as_ref().unwrap())?;
            verify_digest(&hash_file(bundle)?, &index.heap_sha256, "raw capture")?;
            let file = File::open(bundle)?;
            if file.metadata()?.len() != index.heap_bytes {
                return Err(invalid("Heap size changed"));
            }
            return Ok(Self { file, index });
        }
        let sums = checksums(bundle)?;
        for (name, expected) in [
            ("layout.json", index.layout_sha256.as_deref()),
            ("maps.txt", index.maps_sha256.as_deref()),
        ] {
            let expected = expected
                .ok_or_else(|| invalid("This operation requires a layout-assisted index"))?;
            verify_digest(&hash_file(&bundle.join(name))?, expected, name)?;
            verify_digest(&sums[name], expected, name)?;
        }
        // Do not trust embedded index schemas or mappings: compare against the bound sidecars.
        let actual_layout: Layout = serde_json::from_slice(&read_bounded(
            &bundle.join("layout.json"),
            2 * CHUNK as u64,
        )?)?;
        if serde_json::to_value(&actual_layout)? != serde_json::to_value(&index.layout)? {
            return Err(invalid("Index layout differs from capture"));
        }
        let maps_bytes = read_bounded(&bundle.join("maps.txt"), 16 * CHUNK as u64)?;
        let actual_maps = parse_maps(
            std::str::from_utf8(&maps_bytes).map_err(|_| invalid("Invalid maps UTF-8"))?,
            index.heap_bytes,
        )?;
        if serde_json::to_value(actual_maps)? != serde_json::to_value(&index.mappings)? {
            return Err(invalid("Index mappings differ from capture"));
        }
        let path = bundle.join("heap.raw");
        verify_digest(&hash_file(&path)?, &index.heap_sha256, "heap.raw")?;
        verify_digest(&sums["heap.raw"], &index.heap_sha256, "heap.raw")?;
        let file = File::open(path)?;
        if file.metadata()?.len() != index.heap_bytes {
            return Err(invalid("Heap size changed"));
        }
        Ok(Self { file, index })
    }
    fn bytes(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        if length > CHUNK as u64
            || offset
                .checked_add(length)
                .is_none_or(|end| end > self.index.heap_bytes)
        {
            return Err(invalid("Read exceeds heap or 1 MiB request limit"));
        }
        let mut bytes = vec![0; length as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn object(&self, offset: u64) -> Result<Object> {
        self.index
            .objects
            .binary_search_by_key(&offset, |o| o.offset)
            .map(|i| self.index.objects[i].clone())
            .map_err(|_| invalid(format!("No indexed object at 0x{offset:x}")))
    }
    fn class(&self, object: &Object) -> Result<Class> {
        self.index
            .layout
            .as_ref()
            .and_then(|l| l.classes.get(object.class_id))
            .cloned()
            .ok_or_else(|| invalid("Object class is missing from layout"))
    }
    fn validate_object(&mut self, object: &Object, class: &Class) -> Result<()> {
        let layout = self
            .index
            .layout
            .as_ref()
            .ok_or_else(|| invalid("Missing layout"))?;
        let kw = klass_width(layout) as u64;
        if word(&self.bytes(object.offset + 8, kw)?) != number(&class.klass)? {
            return Err(invalid("Indexed class does not match bytes"));
        }
        let size = if class.kind == "array" {
            let length = word(&self.bytes(object.offset + class.length_offset, 4)?);
            if length > i32::MAX as u64 || object.length != Some(length) {
                return Err(invalid("Indexed array length does not match bytes"));
            }
            aligned(
                length
                    .checked_mul(class.scale)
                    .and_then(|n| n.checked_add(class.base))
                    .ok_or_else(|| invalid("Array size overflow"))?,
            )
            .ok_or_else(|| invalid("Array size overflow"))?
        } else {
            class.size
        };
        if size != object.size {
            return Err(invalid("Indexed size does not match layout"));
        }
        let mark = word(&self.bytes(object.offset, 8)?);
        if mark & 3 != 1 || mark >> 40 != 0 {
            return Err(invalid("Indexed mark word is unsupported"));
        }
        Ok(())
    }
    fn reference_target(&self, raw: u64) -> Option<u64> {
        if self.index.identity_mapping {
            return None;
        }
        let address = if self.index.layout.as_ref().is_some_and(generational) {
            gen_address(raw, &self.index.layout.as_ref()?.architecture)?
        } else {
            raw
        };
        translate(&self.index.mappings, address)
    }
    fn scalar(&mut self, offset: u64, kind: &str, resolve_strings: bool) -> Result<Value> {
        let value = word(&self.bytes(offset, width(kind)?)?);
        Ok(match kind {
            "boolean" => json!({"value": value != 0, "valid": value <= 1}),
            "byte" => json!(value as u8 as i8),
            "short" => json!(value as u16 as i16),
            "char" => json!(value as u16),
            "int" => json!(value as u32 as i32),
            "long" => json!(value as i64),
            "float" => {
                let number = f32::from_bits(value as u32);
                if number.is_finite() {
                    json!(number)
                } else {
                    json!(number.to_string())
                }
            }
            "double" => {
                let number = f64::from_bits(value);
                if number.is_finite() {
                    json!(number)
                } else {
                    json!(number.to_string())
                }
            }
            "reference" => {
                let is_gen = self.index.layout.as_ref().is_some_and(generational);
                if value == 0 || (is_gen && value >> 16 == 0) {
                    return Ok(Value::Null);
                }
                let target = self.reference_target(value);
                let object = target.and_then(|t| self.object(t).ok());
                let mut result = json!({"raw": format!("0x{value:x}"), "target_offset": target,
                    "target_class": object.as_ref().map(|o| self.index.class_name(o)), "resolved": object.is_some()});
                result["resolution"] = json!(if self.index.identity_mapping {
                    "unresolved: identity-mapping has no VA translation"
                } else if object.is_some() {
                    "mapped structural candidate; forwarding not checked"
                } else {
                    "unmapped or unindexed (possibly filtered)"
                });
                if is_gen {
                    result["uncolored_address"] = json!(
                        gen_address(value, &self.index.layout.as_ref().unwrap().architecture)
                            .map(|n| format!("0x{n:x}"))
                    );
                    result["color_bits"] = json!(format!("0x{:x}", value & 0xffff));
                } else {
                    result["masked_oop"] = json!(format!("0x{:x}", value & !(0xf << 42)));
                    result["color_bits"] = json!(format!("0x{:x}", value & (0xf << 42)));
                    result["mask_note"] = json!(
                        "diagnostic 42-bit-offset hypothesis only; not a file offset or klass identity"
                    );
                }
                if resolve_strings
                    && let Some(object) =
                        object.filter(|o| self.index.class_name(o) == "java.lang.String")
                {
                    match self.string(&object) {
                        Ok(text) => result["text"] = json!(text),
                        Err(error) => result["text_error"] = json!(error.to_string()),
                    }
                }
                result
            }
            _ => return Err(invalid("Unknown scalar")),
        })
    }
    fn string(&mut self, object: &Object) -> Result<String> {
        let class = self.class(object)?;
        self.validate_object(object, &class)?;
        let find = |name: &str| {
            class
                .fields
                .iter()
                .find(|f| f.name == name)
                .ok_or_else(|| invalid("String layout missing field"))
        };
        let value_offset = find("value")?.offset;
        let coder_offset = find("coder")?.offset;
        let address = word(&self.bytes(object.offset + value_offset, 8)?);
        let coder = word(&self.bytes(object.offset + coder_offset, 1)?);
        let target = self
            .reference_target(address)
            .ok_or_else(|| invalid("String backing array is unmapped"))?;
        let array = self.object(target)?;
        let array_class = self.class(&array)?;
        self.validate_object(&array, &array_class)?;
        if array_class.element != "byte" {
            return Err(invalid("String backing object is not byte[]"));
        }
        let length = array
            .length
            .ok_or_else(|| invalid("Missing String length"))?;
        let bytes = self.bytes(target + array_class.base, length.min(512))?;
        let mut text = match coder {
            0 => bytes.iter().map(|&b| char::from(b)).collect(),
            1 if length % 2 == 0 => String::from_utf16_lossy(
                &bytes
                    .chunks_exact(2)
                    .map(|c| word(c) as u16)
                    .collect::<Vec<_>>(),
            ),
            _ => return Err(invalid("Invalid String coder or UTF-16 length")),
        };
        if length > 512 {
            text.push('…');
        }
        Ok(text)
    }
    pub fn show(&mut self, offset: u64) -> Result<Value> {
        let object = self.object(offset)?;
        let class = self.class(&object)?;
        self.validate_object(&object, &class)?;
        let mut out = json!({"object": self.index.object_view(&object), "evidence": "class identity and bounds match supplied layout; liveness unknown"});
        out["mark_word"] = json!({"raw":format!("0x{:x}", word(&self.bytes(offset,8)?)), "state":"unlocked-or-hashed"});
        out["consistency"] = json!({"scope":"structural, not GC liveness probability", "checks_passed":3, "checks_total":3,
            "checks":["class identity", "mark word shape", "size/length bounds"]});
        if class.kind == "array" {
            let length = object
                .length
                .ok_or_else(|| invalid("Array has no length"))?;
            let mut preview = Vec::new();
            for i in 0..length.min(64) {
                preview.push(self.scalar(
                    offset + class.base + i * class.scale,
                    &class.element,
                    true,
                )?);
            }
            out["element_type"] = json!(class.element);
            out["preview"] = json!(preview);
            out["preview_truncated"] = json!(length > 64);
            out["payload_offset"] = json!(offset + class.base);
            out["payload_bytes"] = json!(length * class.scale);
        } else {
            let mut fields = serde_json::Map::new();
            for field in &class.fields {
                fields.insert(
                    field.name.clone(),
                    self.scalar(offset + field.offset, &field.r#type, true)?,
                );
            }
            out["fields"] = json!(fields);
            if class.name == "java.lang.String" {
                match self.string(&object) {
                    Ok(text) => out["text"] = json!(text),
                    Err(error) => out["text_error"] = json!(error.to_string()),
                }
            }
        }
        Ok(out)
    }
    pub fn extract(&mut self, offset: u64, destination: &Path) -> Result<Value> {
        let object = self.object(offset)?;
        let class = self.class(&object)?;
        self.validate_object(&object, &class)?;
        if class.kind != "array" || class.element == "reference" {
            return Err(invalid("Only primitive array payloads can be extracted"));
        }
        let length = object
            .length
            .ok_or_else(|| invalid("Missing array length"))?
            .checked_mul(class.scale)
            .ok_or_else(|| invalid("Payload overflow"))?;
        self.file.seek(SeekFrom::Start(offset + class.base))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let copied = io::copy(&mut (&mut self.file).take(length), &mut output)?;
        if copied != length {
            return Err(invalid("Truncated payload during extraction"));
        }
        output.flush()?;
        Ok(
            json!({"bytes": length, "sha256": hash_file(destination)?, "source_offset": offset + class.base,
            "element_type": class.element, "byte_order": "little"}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn temporary() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "zgcmaster-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn layout() -> Layout {
        Layout {
            version: 1,
            profile: PROFILE.into(),
            java: "21.0.8+9".into(),
            architecture: "aarch64".into(),
            classes: vec![Class {
                name: "[I".into(),
                klass: "0x700000001000".into(),
                kind: "array".into(),
                size: 24,
                fields: vec![],
                element: "int".into(),
                base: 24,
                scale: 4,
                length_offset: 16,
            }],
        }
    }
    #[test]
    fn mapping_uses_file_offsets_and_aliases() {
        let maps = parse_maps("1000-2000 rw-s 00002000 00:01 1 /memfd:java_heap (deleted)\n5000-6000 rw-s 00002000 00:01 1 /memfd:java_heap (deleted)", 0x4000).unwrap();
        assert_eq!(translate(&maps, 0x1234), Some(0x2234));
        assert_eq!(translate(&maps, 0x5234), Some(0x2234));
        assert_eq!(translate(&maps, 0x2000), None);
        assert!(parse_maps("1000-9000 rw-s 0 00:01 1 /memfd:java_heap", 64).is_err());
    }
    #[test]
    fn scans_across_chunk_boundary_and_rejects_impossible_array() {
        let path = temporary();
        let mut bytes = vec![0; CHUNK + 128];
        let start = CHUNK - 8;
        bytes[start..start + 8].copy_from_slice(&1u64.to_le_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&0x700000001000u64.to_le_bytes());
        bytes[start + 16..start + 20].copy_from_slice(&3u32.to_le_bytes());
        bytes[start + 24..start + 28].copy_from_slice(&(-42i32).to_le_bytes());
        bytes[start + 64..start + 72].copy_from_slice(&1u64.to_le_bytes());
        bytes[start + 72..start + 80].copy_from_slice(&0x700000001000u64.to_le_bytes());
        bytes[start + 80..start + 84].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let index = scan(&path, Some(layout()), vec![]).unwrap();
        assert_eq!(index.objects.len(), 1);
        assert_eq!(index.objects[0].offset, start as u64);
        assert_eq!(index.objects[0].size, 40);
        assert_eq!(index.rejected_headers, 1);
        assert_eq!(index.heap_sha256, format!("{:x}", Sha256::digest(&bytes)));
        let mut reader = Reader {
            file: File::open(&path).unwrap(),
            index,
        };
        let view = reader.show(start as u64).unwrap();
        assert_eq!(view["preview"], json!([-42, 0, 0]));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn refuses_wrong_formats_and_layouts() {
        let path = temporary();
        std::fs::write(&path, b"JAVA PROFILE 1.0.2\0paddingpaddingpadding").unwrap();
        assert!(scan_raw(&path).is_err());
        std::fs::remove_file(path).unwrap();
        let mut l = layout();
        l.classes[0].scale = 8;
        assert!(validate_layout(&l).is_err());
        l.classes[0].scale = 4;
        l.profile = "generational".into();
        assert!(validate_layout(&l).is_err());
    }
    #[test]
    fn prevents_overwriting_output() {
        let path = temporary();
        std::fs::write(&path, vec![0; 32]).unwrap();
        let index = scan_raw(&path).unwrap();
        assert!(write_index(&path, &index).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), vec![0; 32]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn preserves_minimum_instance_at_end_of_file() {
        let path = temporary();
        let mut data = vec![0; 32];
        data[16..24].copy_from_slice(&1u64.to_le_bytes());
        data[24..32].copy_from_slice(&0x700000001000u64.to_le_bytes());
        std::fs::write(&path, data).unwrap();
        let mut profile = layout();
        profile.classes[0].kind = "instance".into();
        profile.classes[0].size = 16;
        let index = scan(&path, Some(profile), vec![]).unwrap();
        assert_eq!(index.objects.len(), 1);
        assert_eq!(index.objects[0].offset, 16);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn capture_binding_rejects_modified_heap_and_index_schema() {
        let dir = temporary();
        std::fs::create_dir(&dir).unwrap();
        let mut data = vec![0; 64];
        data[..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x700000001000u64.to_le_bytes());
        data[16..20].copy_from_slice(&2u32.to_le_bytes());
        data[24..28].copy_from_slice(&1234i32.to_le_bytes());
        data[28..32].copy_from_slice(&(-5678i32).to_le_bytes());
        std::fs::write(dir.join("heap.raw"), &data).unwrap();
        std::fs::write(
            dir.join("layout.json"),
            serde_json::to_vec(&layout()).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("maps.txt"),
            "1000-1040 rw-s 0 00:01 1 /memfd:java_heap (deleted)\n",
        )
        .unwrap();
        std::fs::write(dir.join("consistency.txt"), "test fixture").unwrap();
        let names = ["heap.raw", "layout.json", "maps.txt", "consistency.txt"];
        let sums: String = names
            .iter()
            .map(|name| format!("{}  {name}\n", hash_file(&dir.join(name)).unwrap()))
            .collect();
        std::fs::write(dir.join("SHA256SUMS"), sums).unwrap();
        let mut reader = Reader::open(&dir, scan_bundle(&dir).unwrap()).unwrap();
        assert_eq!(reader.show(0).unwrap()["preview"], json!([1234, -5678]));
        let payload = dir.join("payload.bin");
        assert_eq!(reader.extract(0, &payload).unwrap()["bytes"], 8);
        assert_eq!(std::fs::read(&payload).unwrap(), data[24..32]);
        assert!(reader.extract(0, &payload).is_err());
        let mut modified = scan_bundle(&dir).unwrap();
        modified.layout.as_mut().unwrap().classes[0].name = "made.up.Class".into();
        assert!(Reader::open(&dir, modified).is_err());
        data[24] ^= 1;
        std::fs::write(dir.join("heap.raw"), data).unwrap();
        assert!(scan_bundle(&dir).is_err());
        drop(reader);
        for name in names.into_iter().chain(["SHA256SUMS", "payload.bin"]) {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn refuses_overflowing_fields_and_overlapping_mappings() {
        let mut profile = layout();
        profile.classes[0].kind = "instance".into();
        profile.classes[0].fields = vec![Field {
            name: "bad".into(),
            offset: u64::MAX,
            r#type: "long".into(),
        }];
        assert!(validate_layout(&profile).is_err());
        assert!(parse_maps("1000-1040 rw-s 0 00:01 1 /memfd:java_heap\n1020-1040 rw-s 0 00:01 1 /memfd:java_heap", 64).is_err());
    }
}
