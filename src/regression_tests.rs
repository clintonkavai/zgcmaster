use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn temp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "zgcmaster-regression-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn bound(profile: &str, bindings: &[(&str, &str)]) -> Layout {
    profiles::boot(
        profile,
        &bindings
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
    .unwrap()
}

fn string_bindings(profile: &str, model: &str, max: u64) -> raw_strings::Bindings {
    let narrow = profile.contains("-compressedklass-");
    raw_strings::Bindings::new(
        profile,
        model,
        &BTreeMap::from([
            (
                "java.lang.String".into(),
                if narrow { "0x2000" } else { "0x10000002000" }.into(),
            ),
            (
                "[B".into(),
                if narrow { "0x3000" } else { "0x10000003000" }.into(),
            ),
        ]),
        max,
    )
    .unwrap()
}

fn string_pair(
    data: &mut [u8],
    offset: usize,
    array: usize,
    payload: &[u8],
    coder: u8,
    narrow: bool,
    raw: u64,
) {
    header(
        data,
        offset,
        if narrow { 0x2000 } else { 0x10000002000 },
        narrow,
        None,
    );
    let hash_at = offset + if narrow { 12 } else { 16 };
    let hash = discovery::java_hash(payload, coder);
    data[hash_at..hash_at + 4].copy_from_slice(&hash.to_le_bytes());
    data[hash_at + 4] = coder;
    data[hash_at + 5] = u8::from(hash == 0);
    data[offset + 24..offset + 32].copy_from_slice(&raw.to_le_bytes());
    header(
        data,
        array,
        if narrow { 0x3000 } else { 0x10000003000 },
        narrow,
        Some(payload.len() as u32),
    );
    let base = array + if narrow { 16 } else { 24 };
    data[base..base + payload.len()].copy_from_slice(payload);
}

#[test]
fn strings_stream_all_profiles_encodings_colors_and_chunk_boundary() {
    for profile in profiles::SUPPORTED {
        let narrow = profile.contains("-compressedklass-");
        let models = if profile.contains("-nongen-") {
            vec!["nongen-low42-equals-file-offset"]
        } else {
            vec![
                "gen-amd64-heap-relative-equals-file-offset",
                "gen-aarch64-heap-relative-equals-file-offset",
            ]
        };
        for model in models {
            let bindings = string_bindings(profile, model, 64);
            let raw = |offset: u64, color: u64| {
                if model.starts_with("nongen") {
                    (1 << (42 + color)) | offset
                } else if model.contains("amd64") {
                    ((0x400000000 | offset) << (13 + color)) | (1 << (12 + color)) | 0x510
                } else {
                    ((0x400000000 | offset) << 16) | ((0xf ^ (1 << color)) << 12) | 0x510
                }
            };
            let mut data = vec![0; CHUNK + 96];
            string_pair(&mut data, 0, 128, b"a\xffb", 0, narrow, raw(128, 0));
            string_pair(
                &mut data,
                64,
                256,
                &[0xbb, 3, 0x3d, 0xd8, 0x80, 0xde, 0, 0xd8],
                1,
                narrow,
                raw(256, 1),
            );
            let ha = 64 + if narrow { 12 } else { 16 };
            data[ha..ha + 4].fill(0); // valid, but no cached hash
            string_pair(
                &mut data,
                CHUNK - 8,
                CHUNK + 64,
                b"",
                0,
                narrow,
                raw((CHUNK + 64) as u64, 2),
            );
            let path = temp();
            std::fs::write(&path, data).unwrap();
            let mut out = Vec::new();
            let report = raw_strings::strings(&path, &bindings, 3, false, &mut out).unwrap();
            assert_eq!(report["header_candidates"], 3);
            assert_eq!(report["emitted"], 2);
            assert_eq!(report["heap_sha256"], hash_file(&path).unwrap());
            let rows: Vec<Value> = String::from_utf8(out)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            assert_eq!(rows[1]["text"], "aÿb");
            assert_eq!(rows[2]["text"], "λ🚀�");
            assert_eq!(rows[2]["utf16_units"], 4);
            assert_eq!(rows[2]["text_lossy"], true);
            assert_eq!(rows.last().unwrap()["record"], "complete");
            let strict = raw_strings::strings(&path, &bindings, 0, true, &mut io::sink()).unwrap();
            assert_eq!(strict["emitted"], 2);
            assert_eq!(strict["counts"]["skipped-unhashed"], 1);
            let verified = raw_strings::verify(&path, &bindings, 10, 9).unwrap();
            assert_eq!(verified["sampling"]["sampled"], 3);
            assert_eq!(verified["counts"]["match"], 1);
            assert_eq!(verified["counts"]["zero-hash-match"], 1);
            assert_eq!(verified["counts"]["not-cached"], 1);
            assert_eq!(verified["confirmation_rate"], 1.0);
            assert!(!verified.to_string().contains("λ"));
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn verification_retains_failures_and_sampling_is_reproducible() {
    let bindings = string_bindings(
        profiles::SUPPORTED[1],
        "nongen-low42-equals-file-offset",
        64,
    );
    let mut data = vec![0; 6400];
    for i in 0..100 {
        let at = i * 64;
        string_pair(
            &mut data,
            at,
            at + 32,
            b"abcd",
            0,
            true,
            (1 << 42) | (at + 32) as u64,
        );
        match i / 20 {
            0 => data[at + 24..at + 32].fill(0),
            1 => data[at + 40..at + 44].copy_from_slice(&0x4000u32.to_le_bytes()),
            2 => data[at + 12..at + 16].fill(0),
            3 => data[at + 12] ^= 1,
            _ => (),
        }
    }
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let report = raw_strings::verify(&path, &bindings, 1000, 42).unwrap();
    for status in [
        "unresolved-reference",
        "array-header-mismatch",
        "not-cached",
        "mismatch",
        "match",
    ] {
        assert_eq!(report["counts"][status], 20, "{status}");
    }
    assert_eq!(report["confirmation_rate"], 0.5);
    assert_eq!(report["confirmed_fraction_of_sample"], 0.2);
    let a = raw_strings::verify(&path, &bindings, 10, 42).unwrap();
    let b = raw_strings::verify(&path, &bindings, 10, 42).unwrap();
    let c = raw_strings::verify(&path, &bindings, 10, 43).unwrap();
    assert_eq!(a, b);
    assert_ne!(a["samples"], c["samples"]);
    assert_eq!(a["sampling"]["population"], 100);
    assert!(
        a["samples"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["string_offset"].as_u64().unwrap() > 3200)
    );
    let trawl = raw_strings::strings(&path, &bindings, 1, false, &mut io::sink()).unwrap();
    assert_eq!(trawl["emitted"], 40);
    let small = string_bindings(profiles::SUPPORTED[1], "nongen-low42-equals-file-offset", 3);
    let capped = raw_strings::verify(&path, &small, 1000, 42).unwrap();
    assert_eq!(capped["counts"]["payload-limit"], 60);
    assert!(capped["confirmation_rate"].is_null());
    assert!(raw_strings::verify(&path, &bindings, 0, 0).is_err());
    assert!(raw_strings::verify(&path, &bindings, 10001, 0).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn string_commands_reject_bad_bindings_formats_and_propagate_writer_errors() {
    let ids = BTreeMap::from([
        ("java.lang.String".into(), "0x2000".into()),
        ("[B".into(), "0x3000".into()),
    ]);
    for (profile, model, max) in [
        (profiles::SUPPORTED[1], "unknown", 64),
        (
            profiles::SUPPORTED[3],
            "nongen-low42-equals-file-offset",
            64,
        ),
        (
            profiles::SUPPORTED[1],
            "nongen-low42-equals-file-offset",
            1048577,
        ),
    ] {
        assert!(raw_strings::Bindings::new(profile, model, &ids, max).is_err());
    }
    assert!(
        raw_strings::Bindings::new(
            profiles::SUPPORTED[1],
            "nongen-low42-equals-file-offset",
            &BTreeMap::new(),
            64
        )
        .is_err()
    );
    let path = temp();
    let bindings = string_bindings(
        profiles::SUPPORTED[1],
        "nongen-low42-equals-file-offset",
        64,
    );
    for signature in [b"JAVA PROFILE".as_slice(), b"\x1f\x8b", b"\x7fELF"] {
        let mut data = vec![0; 64];
        data[..signature.len()].copy_from_slice(signature);
        std::fs::write(&path, data).unwrap();
        let mut out = Vec::new();
        assert!(raw_strings::strings(&path, &bindings, 0, false, &mut out).is_err());
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains("\"record\":\"complete\"")
        );
    }
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(raw_strings::strings(&path, &bindings, 0, false, &mut Failing).is_err());
    std::fs::remove_file(path).unwrap();
}
fn header(data: &mut [u8], offset: usize, klass: u64, narrow: bool, length: Option<u32>) {
    data[offset..offset + 8].copy_from_slice(&1u64.to_le_bytes());
    let k = klass.to_le_bytes();
    let kw = if narrow { 4 } else { 8 };
    data[offset + 8..offset + 8 + kw].copy_from_slice(&k[..kw]);
    if let Some(length) = length {
        data[offset + 8 + kw..offset + 12 + kw].copy_from_slice(&length.to_le_bytes());
    }
}

#[test]
fn klass_mask_would_merge_distinct_native_metadata_addresses() {
    let a = 0x10000001000;
    let b = a | (1 << 42);
    assert_eq!(a & !(0xf << 42), b & !(0xf << 42));
    let layout = bound(
        PROFILE,
        &[("[B", &format!("0x{a:x}")), ("[I", &format!("0x{b:x}"))],
    );
    let mut data = vec![0; 64];
    header(&mut data, 0, a, false, Some(0));
    header(&mut data, 32, b, false, Some(0));
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let index = scan(&path, Some(layout), vec![]).unwrap();
    assert_eq!(index.objects.len(), 2);
    assert_ne!(index.objects[0].class_id, index.objects[1].class_id);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn node_discovery_checks_key_hash_value_pairs_links_and_rejects_wrong_hashes() {
    for narrow in [true, false] {
        let path = temp();
        let mut data = vec![0; 160000];
        let node_id = if narrow { 0x4000 } else { 0x10000004000 };
        let fake_id = if narrow { 0x5000 } else { 0x10000005000 };
        let nodes: Vec<_> = (0..200).map(|i| 512 + i * 128 + (i % 7) * 8).collect();
        for (i, &node) in nodes.iter().enumerate() {
            let key = 50000 + i * 200 + (i % 5) * 8;
            let value = key + 64;
            let array = 100000 + i * 208 + (i % 3) * 8;
            let key_text = format!("key-{i:03}");
            let value_text = format!("value-{i:03}");
            string_pair(
                &mut data,
                key,
                array,
                key_text.as_bytes(),
                0,
                narrow,
                (1 << 42) | array as u64,
            );
            string_pair(
                &mut data,
                value,
                array + 80,
                value_text.as_bytes(),
                0,
                narrow,
                (1 << 42) | (array + 80) as u64,
            );
            let hash = discovery::java_hash(key_text.as_bytes(), 0);
            let ka = if narrow { 16 } else { 24 };
            let ha = if narrow { 12 } else { 16 };
            for (at, klass, hash) in [
                (node, node_id, hash ^ (hash >> 16)),
                (
                    30000 + i * 80 + (i % 3) * 8,
                    fake_id,
                    (hash ^ (hash >> 16)) ^ 1,
                ),
            ] {
                header(&mut data, at, klass, narrow, None);
                data[at + ha..at + ha + 4].copy_from_slice(&hash.to_le_bytes());
                data[at + ka..at + ka + 8].copy_from_slice(&((1 << 42) | key as u64).to_le_bytes());
                data[at + ka + 8..at + ka + 16]
                    .copy_from_slice(&((1 << 42) | value as u64).to_le_bytes());
                if i % 2 == 0 {
                    data[at + ka + 16..at + ka + 24]
                        .copy_from_slice(&((1 << 42) | nodes[i + 1] as u64).to_le_bytes());
                }
            }
        }
        std::fs::write(&path, &data).unwrap();
        let options = ScanOptions {
            discover_bindings: true,
            ..Default::default()
        };
        let index = scan_raw_with(&path, &options, None).unwrap();
        let proposals = index.binding_discovery["hashmap_node_discovery"]["proposals"]
            .as_array()
            .unwrap();
        assert_eq!(proposals.len(), 1, "{proposals:?}");
        let proposal = &proposals[0];
        assert_eq!(
            proposal["bindings"]["java.util.HashMap$Node"],
            format!("0x{node_id:x}")
        );
        assert!(proposal["same_klass_next_links"].as_u64().unwrap() > 0);
        assert!(proposal["string_value_pairs"].as_u64().unwrap() >= 3);
        assert_eq!(proposal["exact_shallow_size_known"], false);
        assert_eq!(proposal["automatically_applied"], false);
        for node in nodes {
            let ka = if narrow { 16 } else { 24 };
            data[node + ka + 16..node + ka + 24]
                .copy_from_slice(&((1 << 42) | node as u64).to_le_bytes());
        }
        std::fs::write(&path, data).unwrap();
        let index = scan_raw_with(&path, &options, None).unwrap();
        assert!(
            index.binding_discovery["hashmap_node_discovery"]["proposals"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn string_stream_cannot_complete_after_capture_mutation() {
    let path = temp();
    let mut data = vec![0; 64];
    string_pair(&mut data, 0, 32, b"abc", 0, true, (1 << 42) | 32);
    std::fs::write(&path, data).unwrap();
    struct MutatingWriter {
        path: std::path::PathBuf,
        output: Vec<u8>,
        calls: usize,
    }
    impl Write for MutatingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            if bytes == b"\n" {
                self.calls += 1;
                if self.calls == 2 {
                    // String record emitted, before digest recheck
                    let mut file = OpenOptions::new().write(true).open(&self.path)?;
                    file.seek(SeekFrom::Start(48))?;
                    file.write_all(b"x")?;
                }
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = MutatingWriter {
        path: path.clone(),
        output: vec![],
        calls: 0,
    };
    let bindings = string_bindings(
        profiles::SUPPORTED[1],
        "nongen-low42-equals-file-offset",
        64,
    );
    assert!(raw_strings::strings(&path, &bindings, 0, false, &mut writer).is_err());
    assert!(
        !String::from_utf8(writer.output)
            .unwrap()
            .contains("\"record\":\"complete\"")
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn all_generational_remap_colors_decode_on_both_architectures() {
    let address = 0x400001000u64;
    for color in 0..4u32 {
        let raw = (address << (13 + color)) | (1 << (12 + color)) | 0x510;
        assert_eq!(gen_address(raw, "amd64"), Some(address));
        let raw = (address << 16) | ((0xf ^ (1 << color)) << 12) | 0x510;
        assert_eq!(gen_address(raw, "aarch64"), Some(address));
    }
    assert_eq!(gen_address(0x1510, "amd64"), Some(0));
    assert_eq!(gen_address((address << 16) | 0x3500, "amd64"), None);
}

#[test]
fn narrow_array_length_does_not_become_part_of_class_identity() {
    let profile = profiles::SUPPORTED[3];
    let layout = bound(profile, &[("[B", "0x1001")]);
    let mut data = vec![0; 64];
    header(&mut data, 0, 0x1001, true, Some(3));
    data[16..19].copy_from_slice(b"abc");
    header(&mut data, 32, 0x1001, true, Some(u32::MAX));
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let options = ScanOptions {
        identity_mapping: true,
        layout: Some(layout),
        ..Default::default()
    };
    let index = scan_raw_with(&path, &options, None).unwrap();
    assert_eq!(index.objects.len(), 1);
    assert_eq!(index.objects[0].size, 24);
    let mut reader = Reader::open(&path, index).unwrap();
    assert_eq!(reader.show(0).unwrap()["preview"], json!([97, 98, 99]));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn identity_mode_never_treats_a_reference_as_file_offset() {
    let layout = bound(
        PROFILE,
        &[
            ("java.lang.String", "0x10000001000"),
            ("[B", "0x10000002000"),
        ],
    );
    let mut data = vec![0; 64];
    header(&mut data, 0, 0x10000001000, false, None);
    data[24..32].copy_from_slice(&32u64.to_le_bytes());
    header(&mut data, 32, 0x10000002000, false, Some(3));
    data[56..59].copy_from_slice(b"abc");
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let options = ScanOptions {
        identity_mapping: true,
        layout: Some(layout),
        ..Default::default()
    };
    let index = scan_raw_with(&path, &options, None).unwrap();
    let view = Reader::open(&path, index).unwrap().show(0).unwrap();
    assert_eq!(view["fields"]["value"]["resolved"], false);
    assert!(view["fields"]["value"]["target_offset"].is_null());
    assert!(view.get("text_error").is_some());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn streaming_matches_filter_and_requires_success_footer() {
    let layout = bound(PROFILE, &[("[B", "0x10000001000"), ("[I", "0x10000002000")]);
    let mut data = vec![0; 64];
    header(&mut data, 0, 0x10000001000, false, Some(0));
    header(&mut data, 32, 0x10000002000, false, Some(0));
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let options = ScanOptions {
        only: vec!["[B".into()],
        ..Default::default()
    };
    let mut stream = Vec::new();
    let index = scan_with(
        &path,
        Some(layout.clone()),
        vec![],
        &options,
        Some(&mut stream),
        None,
    )
    .unwrap();
    assert!(index.objects.is_empty());
    assert!(index.streamed);
    assert_eq!(index.class_counts["[B"], 1);
    let rows: Vec<Value> = String::from_utf8(stream)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["record"], "complete");
    let mut stream = Vec::new();
    assert!(
        scan_with(
            &path,
            Some(layout),
            vec![],
            &options,
            Some(&mut stream),
            Some("wrong hash")
        )
        .is_err()
    );
    assert!(
        !String::from_utf8(stream)
            .unwrap()
            .contains("\"record\":\"complete\"")
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn carving_ignores_scratch_magic_and_text_markers() {
    let layout = bound(PROFILE, &[("[B", "0x10000001000")]);
    let mut data = vec![0; 160];
    let gzip = b"\x1f\x8b\x08\0\0\0\0\0\0\0";
    data[8..18].copy_from_slice(gzip); // scratch, no object header or file signature
    header(&mut data, 32, 0x10000001000, false, Some(10));
    data[56..66].copy_from_slice(gzip);
    header(&mut data, 80, 0x10000001000, false, Some(12));
    data[104..108].copy_from_slice(b"\xfe\xed\xfe\xed");
    let path = temp();
    let directory = temp();
    std::fs::write(&path, data).unwrap();
    let options = ScanOptions {
        identity_mapping: true,
        layout: Some(layout),
        ..Default::default()
    };
    let index = scan_raw_with(&path, &options, None).unwrap();
    let mut report = Vec::new();
    Reader::open(&path, index)
        .unwrap()
        .carve(&directory, &mut report)
        .unwrap();
    let entries: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(std::fs::read(&entries[0]).unwrap(), gzip);
    for entry in entries {
        std::fs::remove_file(entry).unwrap();
    }
    std::fs::remove_dir(directory).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn diff_rejects_different_filter_or_layout_and_ignores_klass_rebasing() {
    let mut data = vec![0; 32];
    header(&mut data, 0, 0x10000001000, false, Some(0));
    let path = temp();
    std::fs::write(&path, data).unwrap();
    let mut a = scan(
        &path,
        Some(bound(PROFILE, &[("[B", "0x10000001000")])),
        vec![],
    )
    .unwrap();
    let mut b = scan(
        &path,
        Some(bound(PROFILE, &[("[B", "0x10000001000")])),
        vec![],
    )
    .unwrap();
    b.layout.as_mut().unwrap().classes[0].klass = "0x20000001000".into();
    assert_eq!(
        analysis::diff(&a, &b).unwrap()["class_counts"]["[B"]["delta"],
        0
    );
    a.only.push("[B".into());
    assert!(analysis::diff(&a, &b).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn profile_detection_has_an_inconclusive_state() {
    assert_eq!(analysis::detection(0, 0)["suggestion"], "inconclusive");
    assert_eq!(
        analysis::detection(100, 0)["suggestion"],
        "uncompressed-klass"
    );
    assert_eq!(
        analysis::detection(0, 100)["suggestion"],
        "compressed-klass"
    );
    assert_eq!(analysis::detection(100, 100)["suggestion"], "inconclusive");
}

#[test]
fn scan_separates_fourteen_periodic_groups_from_irregular_wide_headers() {
    let path = temp();
    let mut data = vec![0; 1_000_000];
    for i in 0..1500 {
        for group in 0..14 {
            header(
                &mut data,
                272 + i * 440 + group * 24,
                0x1000 + group as u64,
                true,
                Some(0),
            );
        }
    }
    let mut offset = 700_000;
    for i in 0..200 {
        header(&mut data, offset, 0x900000000800, false, None);
        offset += 32 + (i % 11) * 8;
    }
    std::fs::write(&path, data).unwrap();
    let index = scan_raw(&path).unwrap();
    assert_eq!(index.detection["raw_votes"]["narrow"], 21000);
    assert_eq!(index.detection["excluded_periodic_votes"]["narrow"], 21000);
    assert_eq!(index.detection["wide_votes"], 200);
    assert_eq!(index.detection["suggestion"], "uncompressed-klass");
    let summary = summary(&index);
    assert_eq!(
        summary["raw_header_groups_structural_metadata_candidates_top20"]
            .as_array()
            .unwrap()
            .len(),
        14
    );
    assert_eq!(
        summary["raw_header_groups_object_like_top20"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let output = temp();
    write_index(&output, &index).unwrap();
    let loaded = load_index(&output).unwrap();
    assert_eq!(loaded.header_group_stats.len(), 15);
    let mut old: Value = serde_json::to_value(index).unwrap();
    old.as_object_mut().unwrap().remove("header_group_stats");
    old["detection"] = analysis::detection(0, 21000);
    let old: Index = serde_json::from_value(old).unwrap();
    assert_eq!(
        super::summary(&old)["profile_detection"]["suggestion"],
        "inconclusive"
    );
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(output).unwrap();
}

#[test]
fn discovers_hash_confirmed_pairs_without_binding_them_and_rejects_corruption() {
    let path = temp();
    let mut data = vec![0; 100_000];
    let mut strings = Vec::new();
    let mut arrays = Vec::new();
    let mut offset = 128;
    for i in 0..100 {
        let array = 20_000 + i * 128 + (i % 7) * 8;
        let payload = format!("fixture-string-{i}");
        let hash = payload
            .bytes()
            .fold(0u32, |h, c| h.wrapping_mul(31).wrapping_add(c as u32));
        header(&mut data, offset, 0x2000, true, None);
        data[offset + 12..offset + 16].copy_from_slice(&hash.to_le_bytes());
        data[offset + 24..offset + 32]
            .copy_from_slice(&((1u64 << 42) | array as u64).to_le_bytes());
        header(&mut data, array, 0x3000, true, Some(payload.len() as u32));
        data[array + 16..array + 16 + payload.len()].copy_from_slice(payload.as_bytes());
        strings.push(offset);
        arrays.push(array);
        offset += 40 + (i % 9) * 8;
    }
    std::fs::write(&path, &data).unwrap();
    let options = ScanOptions {
        discover_bindings: true,
        identity_mapping: true,
        ..Default::default()
    };
    let index = scan_raw_with(&path, &options, None).unwrap();
    assert!(index.layout.is_none());
    assert!(index.objects.is_empty());
    let proposals = index.binding_discovery["proposals"].as_array().unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0]["bindings"]["java.lang.String"], "0x2000");
    assert_eq!(proposals[0]["bindings"]["[B"], "0x3000");
    assert_eq!(proposals[0]["automatically_applied"], false);
    assert_eq!(
        proposals[0]["reference_hypothesis"],
        "nongen-low42-equals-file-offset"
    );
    for &array in &arrays {
        data[array + 16] ^= 1;
    }
    std::fs::write(&path, &data).unwrap();
    assert!(discovery::discover(&path, &index).is_err()); // rehash detects mutation
    let failed = scan_raw_with(&path, &options, None).unwrap();
    assert_eq!(failed.binding_discovery["status"], "no-supported-proposal");
    for &offset in &strings {
        data[offset + 24..offset + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    }
    std::fs::write(&path, &data).unwrap();
    let failed = scan_raw_with(&path, &options, None).unwrap();
    assert_eq!(failed.binding_discovery["status"], "no-supported-proposal");
    assert!(scan_raw_with(&path, &options, Some(&mut io::sink())).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn periodicity_never_removes_explicitly_typed_objects() {
    let path = temp();
    let mut data = vec![0; 1600];
    for i in 0..50 {
        header(&mut data, i * 32, 0x10000001000, false, Some(0));
    }
    std::fs::write(&path, data).unwrap();
    let index = scan(
        &path,
        Some(bound(PROFILE, &[("[B", "0x10000001000")])),
        vec![],
    )
    .unwrap();
    assert_eq!(index.objects.len(), 50);
    assert!(index.header_group_stats["wide:0x10000001000"].periodic);
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "scale test: run cargo test --release --offline -- --include-ignored"]
fn streaming_exceeds_two_million_candidates_with_no_object_vector() {
    let path = temp();
    let layout = bound(PROFILE, &[("[B", "0x10000001000"), ("[I", "0x10000002000")]);
    let mut header_bytes = [0; 24];
    header(&mut header_bytes, 0, 0x10000001000, false, Some(0));
    let mut file = io::BufWriter::new(File::create(&path).unwrap());
    for _ in 0..=MAX_OBJECTS {
        file.write_all(&header_bytes).unwrap();
    }
    header(&mut header_bytes, 0, 0x10000002000, false, Some(0));
    file.write_all(&header_bytes).unwrap();
    file.flush().unwrap();
    let mut sink = io::sink();
    let index = scan_with(
        &path,
        Some(layout.clone()),
        vec![],
        &ScanOptions::default(),
        Some(&mut sink),
        None,
    )
    .unwrap();
    assert!(index.objects.is_empty());
    assert_eq!(index.class_counts["[B"], MAX_OBJECTS as u64 + 1);
    let filtered = scan_with(
        &path,
        Some(layout.clone()),
        vec![],
        &ScanOptions {
            only: vec!["[I".into()],
            ..Default::default()
        },
        None,
        None,
    )
    .unwrap();
    assert_eq!(filtered.objects.len(), 1);
    assert!(scan(&path, Some(layout), vec![]).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "scale test: sparse 4 GiB+ capture"]
fn scans_beyond_four_gibibytes_with_64_bit_file_offsets() {
    let path = temp();
    let offset = 4 * 1024 * 1024 * 1024u64;
    let mut file = File::create(&path).unwrap();
    file.set_len(offset + 32).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut bytes = [0; 32];
    header(&mut bytes, 0, 0x10000001000, false, Some(3));
    bytes[24..27].copy_from_slice(b"abc");
    file.write_all(&bytes).unwrap();
    drop(file);
    let options = ScanOptions {
        identity_mapping: true,
        layout: Some(bound(PROFILE, &[("[B", "0x10000001000")])),
        ..Default::default()
    };
    let index = scan_raw_with(&path, &options, None).unwrap();
    assert_eq!(index.objects.len(), 1);
    assert_eq!(index.objects[0].offset, offset);
    assert_eq!(
        Reader::open(&path, index).unwrap().show(offset).unwrap()["preview"],
        json!([97, 98, 99])
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "scale test: two million String resolutions without indexing"]
fn string_trawl_and_reservoir_exceed_object_index_cap() {
    let path = temp();
    let count = MAX_OBJECTS as u64 + 1;
    let array = count * 32;
    let mut string = [0u8; 32];
    header(&mut string, 0, 0x2000, true, None);
    string[12..16].copy_from_slice(&96354u32.to_le_bytes());
    string[24..32].copy_from_slice(&((1 << 42) | array).to_le_bytes());
    let mut file = io::BufWriter::new(File::create(&path).unwrap());
    for _ in 0..count {
        file.write_all(&string).unwrap();
    }
    let mut bytes = [0u8; 24];
    header(&mut bytes, 0, 0x3000, true, Some(3));
    bytes[16..19].copy_from_slice(b"abc");
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    drop(file);
    let bindings = string_bindings(
        profiles::SUPPORTED[1],
        "nongen-low42-equals-file-offset",
        64,
    );
    let trawl = raw_strings::strings(&path, &bindings, 4, false, &mut io::sink()).unwrap();
    assert_eq!(trawl["header_candidates"], count);
    assert_eq!(trawl["counts"]["match"], count);
    assert_eq!(trawl["emitted"], 0);
    let verified = raw_strings::verify(&path, &bindings, 1000, 42).unwrap();
    assert_eq!(verified["sampling"]["population"], count);
    assert_eq!(verified["counts"]["match"], 1000);
    std::fs::remove_file(path).unwrap();
}
