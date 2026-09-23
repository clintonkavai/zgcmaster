use super::*;
use crate::regression_tests::{bound, header, string_bindings, string_pair, temp};

fn options() -> corpus::Options {
    corpus::Options {
        census: Default::default(),
        reference_hypothesis: "nongen-low42-equals-file-offset".into(),
        min_len: 1,
        require_hash: false,
        max_unique: 1000,
        max_text_bytes: 1048576,
    }
}
fn indexed(data: &[u8], layout: Layout) -> (std::path::PathBuf, std::path::PathBuf) {
    let path = temp();
    let index_path = temp();
    std::fs::write(&path, data).unwrap();
    let index = scan_raw_with(
        &path,
        &ScanOptions {
            identity_mapping: true,
            layout: Some(layout),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    write_index(&index_path, &index).unwrap();
    (path, index_path)
}
fn capture(texts: &[&str], rebase: u32) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut data = vec![0; texts.len() * 256];
    for (i, text) in texts.iter().enumerate() {
        let at = i * 256;
        string_pair(
            &mut data,
            at,
            at + 64,
            text.as_bytes(),
            0,
            true,
            (1 << 42) | (at + 64) as u64,
        );
        data[at + 8..at + 12].copy_from_slice(&(0x2000 + rebase).to_le_bytes());
        data[at + 72..at + 76].copy_from_slice(&(0x3000 + rebase).to_le_bytes());
    }
    indexed(
        &data,
        bound(
            profiles::SUPPORTED[1],
            &[
                ("java.lang.String", &format!("0x{:x}", 0x2000 + rebase)),
                ("[B", &format!("0x{:x}", 0x3000 + rebase)),
            ],
        ),
    )
}
fn remove(paths: &[&Path]) {
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}
fn rows(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn census_classification_separates_utf8_anomalies_from_magic_and_binary() {
    for (bytes, kind) in [
        (b"".as_slice(), "empty"),
        (b"hello world", "text"),
        (br#"{"kind":"synthetic"}"#, "json"),
        (b"[1,2]", "json"),
        (b"[not json]", "text"),
        (b"\0\0\xff\x80", "binary"),
        (b"\xff\xd8\xff\xe0", "jpeg"),
        (b"%PDF-1.7", "pdf"),
        (b"plain text ends \xe2\x82", "text-like-invalid-utf8"),
        (b"plain \xff text keeps going", "text-like-invalid-utf8"),
    ] {
        assert_eq!(census::classify(bytes).kind, kind, "{bytes:?}");
    }
    assert_eq!(
        census::classify(b"plain text ends \xe2\x82").utf8,
        "incomplete-tail"
    );
    assert_eq!(
        census::classify(b"plain \xff text keeps going").utf8,
        "invalid-sequence"
    );
    assert!(!census::classify(b"\xff\xd8\xff\xe0").text_like_anomaly);
    assert_eq!(census::classify("日本語のテキスト".as_bytes()).kind, "text");
}

#[test]
fn census_counts_whole_indexed_arrays_regions_and_excluded_large_payloads() {
    let region = 16 * 1024 * 1024;
    let mut data = vec![0; region + 256];
    let payloads: Vec<(usize, &[u8])> = vec![
        (0, b""),
        (128, br#"{"example":true}"#),
        (256, b"\xff\xd8\xff\xe0"),
        (384, b"plain text ends \xe2\x82"),
        (
            512,
            b"this synthetic payload exceeds the configured length bound",
        ),
        (
            768,
            b"\xff\xd8\xff\xe0 synthetic oversized magic payload, not a validated JPEG",
        ),
        (region + 128, b"hello world"),
    ];
    for &(at, payload) in &payloads {
        header(&mut data, at, 0x3000, true, Some(payload.len() as u32));
        data[at + 16..at + 16 + payload.len()].copy_from_slice(payload);
    }
    data[2048..2052].copy_from_slice(b"\xff\xd8\xff\xe0"); // scratch magic is not indexed
    let (path, index) = indexed(&data, bound(profiles::SUPPORTED[1], &[("[B", "0x3000")]));
    let report = census::census(
        &path,
        load_index(&index).unwrap(),
        census::Options {
            max_bytes: 32,
            region_bytes: region as u64,
        },
    )
    .unwrap();
    assert_eq!(report["indexed_byte_arrays"], 7);
    assert_eq!(report["classified_arrays"], 6);
    assert_eq!(report["formats"]["jpeg"]["count"], 2);
    assert_eq!(report["coverage"]["prefix_only_magic"]["jpeg"]["count"], 1);
    assert_eq!(report["coverage"]["full_payload_arrays"], 5);
    assert_eq!(report["coverage"]["over_limit_arrays"], 2);
    assert_eq!(report["coverage"]["unclassified_arrays"], 1);
    assert_eq!(report["formats"]["unclassified-over-limit"]["count"], 1);
    assert_eq!(report["text_like_utf8_anomalies"], 1);
    assert_eq!(report["regions"]["0"]["arrays"], 6);
    assert_eq!(report["regions"][region.to_string()]["arrays"], 1);
    let total: u64 = report["formats"]
        .as_object()
        .unwrap()
        .values()
        .map(|t| t["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 7);
    let mut changed = load_index(&index).unwrap();
    changed.objects[1].length = Some(1);
    assert!(census::census(&path, changed, census::Options::default()).is_err());
    data[144] ^= 1;
    std::fs::write(&path, data).unwrap();
    assert!(census::census(&path, load_index(&index).unwrap(), Default::default()).is_err());
    remove(&[&path, &index]);
}

#[test]
fn corpus_diff_is_set_based_with_rebased_ids_census_deltas_and_regex_hits() {
    let (a, ia) = capture(&["common", "common", "gone"], 0);
    let (b, ib) = capture(
        &["common", "FATAL synthetic event", "{DEMO} synthetic"],
        0x3000,
    );
    let pack=patterns::Pack::parse(br#"{"version":1,"patterns":[{"name":"fatal","regex":"FATAL"},{"name":"marker","regex":"\\{DEMO\\}"}]}"#).unwrap();
    let mut out = Vec::new();
    let report =
        corpus::diff_captures(&a, &ia, &b, &ib, &options(), Some(&pack), &mut out).unwrap();
    assert_eq!(report["new_strings"], 2);
    assert_eq!(report["gone_strings"], 1);
    assert_eq!(report["unchanged_strings"], 1);
    assert_eq!(report["regex_new_strings"]["fatal"], 1);
    assert_eq!(report["regex_new_strings"]["marker"], 1);
    assert_eq!(report["census_deltas"]["text"]["count_delta"], 0);
    assert_eq!(report["before_string_coverage"]["unique_strings"], 2);
    let records = rows(&out);
    assert_eq!(records.len(), 5);
    assert_eq!(records.last().unwrap()["record"], "complete");
    let self_diff =
        corpus::diff_captures(&a, &ia, &a, &ia, &options(), None, &mut io::sink()).unwrap();
    assert_eq!(self_diff["new_strings"], 0);
    assert_eq!(self_diff["gone_strings"], 0);
    remove(&[&a, &ia, &b, &ib]);
}

#[test]
fn corpus_limit_refuses_without_partial_completion_and_wrong_indexes_fail() {
    let (a, ia) = capture(&["common", "gone"], 0);
    let (b, ib) = capture(&["common", "new"], 0);
    let mut opts = options();
    opts.max_unique = 1;
    let mut out = Vec::new();
    assert!(corpus::diff_captures(&a, &ia, &b, &ib, &opts, None, &mut out).is_err());
    assert!(out.is_empty());
    opts = options();
    opts.max_text_bytes = 1;
    assert!(corpus::diff_captures(&a, &ia, &b, &ib, &opts, None, &mut out).is_err());
    assert!(corpus::diff_captures(&a, &ib, &b, &ia, &options(), None, &mut out).is_err());
    let mut index = load_index(&ib).unwrap();
    index.only = vec!["java.lang.String".into()];
    let wrong = temp();
    write_index(&wrong, &index).unwrap();
    assert!(corpus::diff_captures(&a, &ia, &b, &wrong, &options(), None, &mut out).is_err());
    remove(&[&a, &ia, &b, &ib, &wrong]);
}

#[test]
fn dictionary_stream_checks_pair_hashes_and_reports_cycles_without_walking_them() {
    for narrow in [true, false] {
        let profile = if narrow {
            profiles::SUPPORTED[1]
        } else {
            profiles::SUPPORTED[0]
        };
        let bindings = string_bindings(profile, "nongen-low42-equals-file-offset", 1024);
        let mut data = vec![0; 512];
        string_pair(
            &mut data,
            128,
            320,
            b"synthetic.key",
            0,
            narrow,
            (1 << 42) | 320,
        );
        string_pair(
            &mut data,
            192,
            384,
            b"FATAL synthetic value",
            0,
            narrow,
            (1 << 42) | 384,
        );
        let node = if narrow { 0x4000 } else { 0x10000004000 };
        let ka = if narrow { 16 } else { 24 };
        let ha = if narrow { 12 } else { 16 };
        let hash = discovery::java_hash(b"synthetic.key", 0);
        let spread = hash ^ (hash >> 16);
        for at in [0, 64] {
            header(&mut data, at, node, narrow, None);
            data[at + ha..at + ha + 4].copy_from_slice(&spread.to_le_bytes());
            data[at + ka..at + ka + 8].copy_from_slice(&((1u64 << 42) | 128).to_le_bytes());
        }
        data[ka + 8..ka + 16].copy_from_slice(&((1u64 << 42) | 192).to_le_bytes());
        data[ka + 16..ka + 24].copy_from_slice(&(1u64 << 42).to_le_bytes()); // self-reference
        let path = temp();
        std::fs::write(&path, &data).unwrap();
        let mut out = Vec::new();
        let report =
            dictionaries::dictionaries(&path, &bindings, &[node], true, None, &mut out).unwrap();
        assert_eq!(report["header_candidates"], 2);
        assert_eq!(report["emitted"], 1);
        assert_eq!(report["counts"]["null-value"], 1);
        let records = rows(&out);
        assert_eq!(records[1]["key"], "synthetic.key");
        assert_eq!(records[1]["value"], "FATAL synthetic value");
        assert_eq!(records[1]["next"]["status"], "self-reference");
        assert!(records[1]["live"].is_null());
        data[192 + ha..192 + ha + 4].fill(0);
        std::fs::write(&path, &data).unwrap();
        let report =
            dictionaries::dictionaries(&path, &bindings, &[node], true, None, &mut io::sink())
                .unwrap();
        assert_eq!(report["emitted"], 0);
        assert_eq!(report["counts"]["skipped-unhashed-pair"], 1);
        data[ha] ^= 1;
        std::fs::write(&path, &data).unwrap();
        let report =
            dictionaries::dictionaries(&path, &bindings, &[node], false, None, &mut io::sink())
                .unwrap();
        assert_eq!(report["emitted"], 0);
        assert_eq!(report["counts"]["node-spread-hash-mismatch"], 1);
        assert!(
            dictionaries::dictionaries(&path, &bindings, &[], false, None, &mut io::sink())
                .is_err()
        );
        remove(&[&path]);
    }
}

#[test]
fn regex_packs_are_bounded_named_and_do_not_filter_string_streams() {
    for bad in [
        br#"{"version":2,"patterns":[]}"#.as_slice(),
        br#"{"version":1,"patterns":[{"name":"a","regex":"(?=x)"}]}"#,
        br#"{"version":1,"patterns":[{"name":"a","regex":"x"},{"name":"a","regex":"y"}]}"#,
        br#"{"version":1,"patterns":[{"name":"not an id","regex":"x"}]}"#,
    ] {
        assert!(patterns::Pack::parse(bad).is_err());
    }
    let pack = patterns::Pack::parse(
        br#"{"version":1,"patterns":[{"name":"fatal","regex":"(?i)fatal"}]}"#,
    )
    .unwrap();
    assert_eq!(pack.matches("FATAL FATAL"), vec!["fatal"]);
    assert!(pack.matches("hello").is_empty());
    let (path, index) = capture(&["FATAL synthetic", "normal"], 0);
    let binding = string_bindings(
        profiles::SUPPORTED[1],
        "nongen-low42-equals-file-offset",
        1024,
    );
    let mut out = Vec::new();
    let report =
        raw_strings::strings_with_pack(&path, &binding, 1, false, Some(&pack), &mut out).unwrap();
    assert_eq!(report["emitted"], 2);
    assert_eq!(rows(&out)[1]["regex_matches"], json!(["fatal"]));
    assert_eq!(rows(&out)[2]["regex_matches"], json!([]));
    remove(&[&path, &index]);
}
