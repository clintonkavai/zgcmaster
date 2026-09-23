use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zgcmaster-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let mut data = [0u8; 64];
        data[..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        data[12..16].copy_from_slice(&96354u32.to_le_bytes());
        data[24..32].copy_from_slice(&((1u64 << 42) | 32).to_le_bytes());
        data[32..40].copy_from_slice(&1u64.to_le_bytes());
        data[40..44].copy_from_slice(&0x3000u32.to_le_bytes());
        data[44..48].copy_from_slice(&3u32.to_le_bytes());
        data[48..51].copy_from_slice(b"abc");
        fs::write(dir.join("heap.raw"), data).unwrap();
        Self { dir }
    }
    fn command(&self, name: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zgcmaster"));
        command.arg(name).arg(self.dir.join("heap.raw")).args([
            "--boot-profile",
            "hotspot21-zgc-nongen-compressedklass-le64",
            "--bind",
            "java.lang.String=0x2000",
            "--bind",
            "[B=0x3000",
            "--reference-hypothesis",
            "nongen-low42-equals-file-offset",
        ]);
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for entry in fs::read_dir(&self.dir).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(&self.dir).unwrap();
    }
}

#[test]
fn cli_trawl_is_jsonl_private_and_never_overwrites() {
    let fixture = Fixture::new();
    let output = fixture.dir.join("strings.jsonl");
    let run = fixture
        .command("strings")
        .args(["--min-len", "3", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(run.status.success(), "{:?}", run.stderr);
    let summary: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(summary["emitted"], 1);
    assert!(!String::from_utf8(run.stdout).unwrap().contains("abc"));
    let bytes = fs::read(&output).unwrap();
    let rows: Vec<Value> = String::from_utf8(bytes.clone())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows[1]["text"], "abc");
    assert_eq!(rows.last().unwrap()["record"], "complete");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        !fixture
            .command("strings")
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), bytes);
    let heap = fixture.dir.join("heap.raw");
    let original = fs::read(&heap).unwrap();
    assert!(
        !fixture
            .command("strings")
            .arg("--output")
            .arg(&heap)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(heap).unwrap(), original);
}

#[test]
fn cli_verify_reports_samples_without_text_and_rejects_inapplicable_flags() {
    let fixture = Fixture::new();
    let run = fixture
        .command("verify-bindings")
        .args(["--samples", "10", "--seed", "42"])
        .output()
        .unwrap();
    assert!(run.status.success(), "{:?}", run.stderr);
    let report: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(report["sampling"]["population"], 1);
    assert_eq!(report["counts"]["match"], 1);
    assert_eq!(report["confirmation_rate"], 1.0);
    assert!(!String::from_utf8(run.stdout).unwrap().contains("abc"));
    for (command, flags) in [
        ("strings", vec!["--samples", "10"]),
        ("verify-bindings", vec!["--min-len", "1"]),
        ("strings", vec!["--min-len", "-1"]),
        ("strings", vec!["--max-bytes", "1048577"]),
        ("strings", vec!["--require-hash", "--require-hash"]),
        ("verify-bindings", vec!["--samples", "0"]),
        ("verify-bindings", vec!["--samples", "10001"]),
        ("strings", vec!["--bind", "[B=0x3000"]),
    ] {
        let path = fixture.dir.join("invalid.json");
        let run = fixture
            .command(command)
            .args(flags)
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!run.status.success());
        assert!(!path.exists());
    }
    let run = Command::new(env!("CARGO_BIN_EXE_zgcmaster"))
        .arg("strings")
        .arg(fixture.dir.join("heap.raw"))
        .args([
            "--boot-profile",
            "hotspot21-zgc-nongen-compressedklass-le64",
            "--bind",
            "java.lang.String=0x2000",
            "--bind",
            "[B=0x3000",
        ])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(
        String::from_utf8(run.stderr)
            .unwrap()
            .contains("Missing --reference-hypothesis")
    );
}
