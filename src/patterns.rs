//! Caller-owned regex packs: bounded compilation, names in reports, no built-in private rules.
use super::*;
use regex::{RegexSet, RegexSetBuilder};
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    version: u32,
    patterns: Vec<Pattern>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pattern {
    name: String,
    regex: String,
}

pub struct Pack {
    names: Vec<String>,
    expressions: RegexSet,
    sha256: String,
}
impl Pack {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&read_bounded(path, 64 * 1024)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 64 * 1024 {
            return Err(invalid("Regex pack exceeds 64 KiB"));
        }
        let definition: Definition = serde_json::from_slice(bytes)?;
        if definition.version != 1
            || definition.patterns.is_empty()
            || definition.patterns.len() > 64
        {
            return Err(invalid("Regex pack needs version 1 and 1..64 patterns"));
        }
        let mut names = BTreeSet::new();
        for p in &definition.patterns {
            if p.name.is_empty()
                || p.name.len() > 64
                || !p
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                || !names.insert(p.name.clone())
                || p.regex.is_empty()
                || p.regex.len() > 2048
            {
                return Err(invalid(
                    "Pattern names must be unique ASCII identifiers (1..64 bytes); regexes 1..2048 bytes",
                ));
            }
        }
        let expressions = RegexSetBuilder::new(definition.patterns.iter().map(|p| &p.regex))
            .size_limit(4*1024*1024).dfa_size_limit(4*1024*1024).nest_limit(64).build()
            .map_err(|_| invalid("Invalid or over-complex regex pack (Rust regex syntax; no lookaround/backreferences)"))?;
        Ok(Self {
            names: definition.patterns.into_iter().map(|p| p.name).collect(),
            expressions,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }
    pub fn matches(&self, text: &str) -> Vec<&str> {
        self.expressions
            .matches(text)
            .iter()
            .map(|i| self.names[i].as_str())
            .collect()
    }
    pub fn metadata(&self) -> Value {
        json!({"sha256":self.sha256,"pattern_names":self.names,"semantics":"one hit per pattern per text, not occurrence counts","engine":"rust-regex"})
    }
}
