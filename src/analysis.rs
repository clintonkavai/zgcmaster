use super::*;

pub(crate) fn detection(wide: u64, narrow: u64) -> Value {
    let total = wide + narrow;
    let confidence = if total == 0 {
        0.0
    } else {
        wide.max(narrow) as f64 / total as f64
    };
    json!({"suggestion":if total < 32 || confidence < 0.8 {"inconclusive"} else if wide > narrow {"uncompressed-klass"} else {"compressed-klass"},
        "confidence":confidence,"confidence_kind":"heuristic vote share, not calibrated probability",
        "wide_votes":wide,"narrow_votes":narrow,"automatic_profile_selection":false,
        "caveat":"Payload words and stale copies can mimic headers; generation, JDK version and class names are not inferred."})
}

pub fn diff(before: &Index, after: &Index) -> Result<Value> {
    let a = before
        .layout
        .as_ref()
        .ok_or_else(|| invalid("Diff requires typed indexes"))?;
    let b = after
        .layout
        .as_ref()
        .ok_or_else(|| invalid("Diff requires typed indexes"))?;
    if a.profile != b.profile
        || a.java != b.java
        || a.architecture != b.architecture
        || before.only != after.only
        || before.identity_mapping != after.identity_mapping
        || before.mode != after.mode
    {
        return Err(invalid(
            "Diff requires matching profile, JDK, architecture, mode and --only selection",
        ));
    }
    let schemas = |l: &Layout| -> Result<BTreeMap<String, Value>> {
        l.classes
            .iter()
            .map(|c| {
                let mut v = serde_json::to_value(c)?;
                v.as_object_mut().unwrap().remove("klass");
                Ok((c.name.clone(), v))
            })
            .collect()
    };
    if schemas(a)? != schemas(b)? {
        return Err(invalid("Class schemas differ; counts are not comparable"));
    }
    let left = summary(before);
    let right = summary(after);
    let left = left["class_counts"].as_object().unwrap();
    let right = right["class_counts"].as_object().unwrap();
    let mut changes = BTreeMap::new();
    for name in left.keys().chain(right.keys()) {
        let old = left.get(name).and_then(Value::as_u64).unwrap_or(0);
        let new = right.get(name).and_then(Value::as_u64).unwrap_or(0);
        changes.insert(
            name,
            json!({"before":old,"after":new,"delta":new as i64-old as i64}),
        );
    }
    Ok(
        json!({"before_sha256":before.heap_sha256,"after_sha256":after.heap_sha256,"class_counts":changes,
        "semantics":"Structural candidate count deltas, not allocations, retained size, liveness or cross-capture object identity.",
        "capture_discipline":"Caller must ensure equivalent capture/GC discipline; index metadata cannot prove it."}),
    )
}

impl Reader {
    /// Sniff only payload starts of header-validated, indexed byte arrays.
    /// Entire array is exported, not a claimed decoded/validated file.
    pub fn carve(&mut self, directory: &Path, mut output: impl Write) -> Result<()> {
        std::fs::create_dir(directory)?;
        for i in 0..self.index.objects.len() {
            let object = self.index.objects[i].clone();
            let class = self.class(&object)?;
            if class.kind != "array" || class.element != "byte" {
                continue;
            }
            self.validate_object(&object, &class)?;
            let length = object.length.unwrap_or(0);
            let prefix = self.bytes(object.offset + class.base, length.min(32))?;
            let kind = sniff(&prefix);
            if let Some(kind) = kind {
                let path = directory.join(format!("{:016x}.{kind}", object.offset));
                let extraction = self.extract(object.offset, &path)?;
                serde_json::to_writer(
                    &mut output,
                    &json!({"object_offset":object.offset,"format_hint":kind,
                    "validation":"indexed byte[] header + length bounds + payload-start magic; contents not fully parsed",
                    "path":path,"extraction":extraction}),
                )?;
                output.write_all(b"\n")?;
            }
        }
        output.flush()?;
        Ok(())
    }
}

pub(crate) fn sniff(p: &[u8]) -> Option<&'static str> {
    if p.len() >= 10 && p.starts_with(&[0x1f, 0x8b, 8]) && p[3] & 0xe0 == 0 {
        Some("gz")
    } else if p.len() >= 4 && p.starts_with(&[0xff, 0xd8, 0xff]) && (0xc0..=0xfe).contains(&p[3]) {
        Some("jpg")
    } else if p.len() >= 24 && p.starts_with(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR") {
        Some("png")
    } else if p.len() >= 10 && (p.starts_with(b"GIF87a") || p.starts_with(b"GIF89a")) {
        Some("gif")
    } else if p.len() >= 30 && p.starts_with(b"PK\x03\x04") {
        Some("zip")
    } else {
        None
    } // No JKS/PEM based on a magic or text marker alone.
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn magic_is_not_enough_for_jks_or_pem() {
        assert_eq!(sniff(b"\xfe\xed\xfe\xedgarbage"), None);
        assert_eq!(sniff(b"-----BEGIN CERTIFICATE-----"), None);
        assert_eq!(sniff(b"\x1f\x8b\x08\0\0\0\0\0\0\0"), Some("gz"));
        assert_eq!(sniff(b"xx\x1f\x8b\x08\0\0\0\0\0\0\0"), None);
    }
}
