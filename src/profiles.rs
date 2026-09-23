//! Layout templates are reusable; native class identities are capture-specific.
use super::*;

pub const SUPPORTED: [&str; 4] = [
    PROFILE,
    "hotspot21-zgc-nongen-compressedklass-le64",
    "hotspot21-zgc-gen-uncompressed-le64",
    "hotspot21-zgc-gen-compressedklass-le64",
];

pub fn boot(profile: &str, bindings: &BTreeMap<String, String>) -> Result<Layout> {
    if !SUPPORTED.contains(&profile) {
        return Err(invalid("Unknown boot profile"));
    }
    let narrow = profile.contains("-compressedklass-");
    let mut classes = Vec::new();
    let mut instance = |name: &str, size, fields: &[(&str, u64, &str)]| {
        classes.push(Class {
            name: name.into(),
            klass: bindings.get(name).cloned().unwrap_or("UNBOUND".into()),
            kind: "instance".into(),
            size,
            fields: fields
                .iter()
                .map(|(n, o, t)| Field {
                    name: (*n).into(),
                    offset: *o,
                    r#type: (*t).into(),
                })
                .collect(),
            element: String::new(),
            base: 0,
            scale: 0,
            length_offset: 0,
        });
    };
    instance(
        "java.lang.String",
        32,
        if narrow {
            &[
                ("hash", 12, "int"),
                ("coder", 16, "byte"),
                ("hashIsZero", 17, "boolean"),
                ("value", 24, "reference"),
            ]
        } else {
            &[
                ("hash", 16, "int"),
                ("coder", 20, "byte"),
                ("hashIsZero", 21, "boolean"),
                ("value", 24, "reference"),
            ]
        },
    );
    instance(
        "java.util.ArrayList",
        32,
        if narrow {
            &[
                ("modCount", 12, "int"),
                ("size", 16, "int"),
                ("elementData", 24, "reference"),
            ]
        } else {
            &[
                ("modCount", 16, "int"),
                ("size", 20, "int"),
                ("elementData", 24, "reference"),
            ]
        },
    );
    instance(
        "java.util.HashMap$Node",
        if narrow { 40 } else { 48 },
        if narrow {
            &[
                ("hash", 12, "int"),
                ("key", 16, "reference"),
                ("value", 24, "reference"),
                ("next", 32, "reference"),
            ]
        } else {
            &[
                ("hash", 16, "int"),
                ("key", 24, "reference"),
                ("value", 32, "reference"),
                ("next", 40, "reference"),
            ]
        },
    );
    for (name, element, scale) in [("[B", "byte", 1), ("[I", "int", 4), ("[J", "long", 8)] {
        classes.push(Class {
            name: name.into(),
            klass: bindings.get(name).cloned().unwrap_or("UNBOUND".into()),
            kind: "array".into(),
            size: if narrow { 16 } else { 24 },
            fields: vec![],
            element: element.into(),
            base: if narrow { 16 } else { 24 },
            scale,
            length_offset: if narrow { 12 } else { 16 },
        });
    }
    for name in bindings.keys() {
        if !classes.iter().any(|c| &c.name == name) {
            return Err(invalid(format!("No built-in layout for {name}")));
        }
    }
    if !bindings.is_empty() {
        classes.retain(|c| bindings.contains_key(&c.name));
    }
    Ok(Layout {
        version: 1,
        profile: profile.into(),
        java: "21.0-template".into(),
        // Field templates apply to both supported CPUs. Do not invent which CPU
        // produced a metadata-free capture (generational oop encodings differ).
        architecture: "unspecified".into(),
        classes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates_require_capture_specific_identities() {
        for profile in SUPPORTED {
            assert!(validate_layout(&boot(profile, &BTreeMap::new()).unwrap()).is_err());
            let bindings = BTreeMap::from([("[B".into(), "0x1000".into())]);
            validate_layout(&boot(profile, &bindings).unwrap()).unwrap();
        }
    }
}
