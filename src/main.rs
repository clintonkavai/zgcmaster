use serde_json::json;
use std::{
    env,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};
use zgcmaster::{
    Error, Layout, Reader, Result, ScanOptions, load_index, number, scan_bundle_with,
    scan_raw_with, summary, write_index,
};

const HELP: &str = "zgcmaster — raw ZGC backing-file reader

Commands:
  scan BUNDLE INDEX.json [OPTIONS]        Index known layouts in a verified capture
  scan-raw HEAP.raw INDEX.json [OPTIONS]  Raw statistics or bound boot layouts
  summary INDEX.json                      Counts, capture hash and limitations
  list INDEX.json [CLASS_SUBSTRING]        Object candidates as JSON lines
  show BUNDLE INDEX.json OFFSET            Decode fields or first 64 array elements
  dump BUNDLE INDEX.json CLASS_SUBSTRING    Decode matching candidates as JSON lines
  extract BUNDLE INDEX.json OFFSET OUT     Export a primitive array payload
  carve SOURCE INDEX.json NEW_DIRECTORY   Sniff/export indexed byte[] payloads (JSONL)
  diff BEFORE.json AFTER.json             Comparable structural class-count deltas
  profiles                               List built-in profile names
  boot-profile PROFILE                   Print UNBOUND boot layout templates
  strings HEAP.raw [STRING_OPTIONS]       Stream hypothesis-resolved Strings (JSONL)
  verify-bindings HEAP.raw [STRING_OPTIONS]  Sample String/byte[] cached hashes (JSON)
  census SOURCE INDEX.json [CENSUS_OPTIONS]  Classify every indexed byte[] candidate
  dictionaries HEAP.raw [STRING_OPTIONS] --node-klass ID [--node-klass ...]
                                         Stream Node-prefix String key/value pairs
  diff-captures BEFORE BEFORE_INDEX AFTER AFTER_INDEX [DIFF_OPTIONS]
                                         String-set changes plus byte[] census deltas

Scan options:
  --only CLASS,CLASS      Exact JVM class names; repeatable, e.g. '[B,[I,[J'
  --jsonl NEW_FILE        Stream candidates without the 2M in-memory cap;
                         INDEX becomes a summary, not a random-access index
  --identity-mapping     File offsets direct; all object references unresolved
  --discover-bindings    scan-raw only: propose String/byte[] and Node-prefix IDs using bounded
                         samples, cached hashes and explicit mapping hypotheses;
                         never auto-applies bindings; no --jsonl or typed layout
Raw-only options (require --identity-mapping):
  --layout FILE          Explicit capture-specific layout
  --boot-profile PROFILE --bind 'CLASS=0xKLASS' [--bind ...]
                         Built-in layouts plus caller-supplied class identities

String commands (raw files; no index or maps needed):
  --boot-profile PROFILE --bind 'java.lang.String=ID' --bind '[B=ID'
  --reference-hypothesis MODEL   Required, explicit file-offset hypothesis:
    nongen-low42-equals-file-offset
    gen-aarch64-heap-relative-equals-file-offset
    gen-amd64-heap-relative-equals-file-offset
  --output NEW_FILE       Optional private output file; default stdout
  --max-bytes N           Payload bound (default 65536, maximum 1048576)
  --min-len N             strings only: minimum UTF-16 units (default 1)
  --require-hash          strings/dictionaries: require cached String hashes (both dictionary sides)
  --samples N --seed N    verify-bindings only (defaults 1000, 0; max 10000)
                         Uniform header sampling before reference resolution;
                         reports failures and conditional hash-match rates, no text
  --node-klass ID         dictionaries only: repeat for compatible Node families
  --regex-pack FILE       strings/dictionaries/diff-captures: versioned user regex pack
                         Matches are labeled; output is not filtered by the pack

Census/diff options:
  --output NEW_FILE       Private output file (default stdout); diff emits JSONL
  --max-bytes N           Full-payload bound (default/max 1048576); excess gets magic hints only
  --region-bytes N        UTF-8 anomaly regions (default 67108864; 16 MiB..1 GiB)
  --reference-hypothesis MODEL  Required for diff-captures; taken with each index's bindings
  --min-len N --require-hash    Diff String filters (default min-len 1, allow unhashed)
  --max-unique N          Diff bound per capture (default 250000; max 2000000)
  --max-text-bytes N      Diff stored UTF-8 bound per capture (default 67108864; max 536870912)
                         Exceeding corpus bounds refuses the diff, never invents gone strings

Offsets accept decimal or 0x-prefixed hex. Files are never overwritten.
SOURCE is a verified bundle directory or a raw file with an identity-mode index.
Java 21 ZGC (generational/non-generational), compressed/uncompressed klass,
uncompressed object references, little-endian, 8-byte alignment. No liveness claims.
";
fn print(value: &impl serde::Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}
fn line(value: &impl serde::Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}
fn scan_command(command: &str, input: &str, output: &str, args: &[String]) -> Result<()> {
    let mut options = ScanOptions::default();
    let mut jsonl = None;
    let mut boot = None;
    let mut bindings = std::collections::BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        if flag == "--identity-mapping" {
            options.identity_mapping = true;
            continue;
        }
        if flag == "--discover-bindings" {
            options.discover_bindings = true;
            continue;
        }
        let value = args
            .get(i)
            .ok_or_else(|| Error::Invalid(format!("Missing value for {flag}")))?;
        i += 1;
        match flag.as_str() {
            "--only" => options.only.extend(value.split(',').map(str::to_string)),
            "--jsonl" if jsonl.is_none() => jsonl = Some(value),
            "--layout" if options.layout.is_none() => {
                options.layout = Some(serde_json::from_slice::<Layout>(&zgcmaster::read_bounded(
                    Path::new(value),
                    2 * 1024 * 1024,
                )?)?)
            }
            "--boot-profile" if boot.is_none() => boot = Some(value),
            "--bind" => {
                let (name, id) = value
                    .split_once('=')
                    .ok_or_else(|| Error::Invalid("Use --bind CLASS=0xKLASS".into()))?;
                number(id)?;
                if bindings.insert(name.into(), id.into()).is_some() {
                    return Err(Error::Invalid("Duplicate class binding".into()));
                }
            }
            _ => {
                return Err(Error::Invalid(format!(
                    "Unknown or repeated option: {flag}"
                )));
            }
        }
    }
    options.only.sort();
    options.only.dedup();
    if command == "scan" && (options.layout.is_some() || boot.is_some() || !bindings.is_empty()) {
        return Err(Error::Invalid(
            "Bundle scans use their verified layout; raw layout options are not allowed".into(),
        ));
    }
    if let Some(profile) = boot {
        if bindings.is_empty() || options.layout.is_some() {
            return Err(Error::Invalid(
                "--boot-profile needs --bind and cannot combine with --layout".into(),
            ));
        }
        options.layout = Some(zgcmaster::profiles::boot(profile, &bindings)?);
    } else if !bindings.is_empty() {
        return Err(Error::Invalid("--bind needs --boot-profile".into()));
    }
    if Path::new(output).exists() {
        return Err(Error::Invalid("Index output already exists".into()));
    }
    if jsonl.is_some_and(|p| p == output || p == input) {
        return Err(Error::Invalid("Outputs and input must be distinct".into()));
    }
    let mut writer = jsonl
        .map(|p| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .map(io::BufWriter::new)
        })
        .transpose()?;
    let stream = writer.as_mut().map(|w| w as &mut dyn Write);
    let index = if command == "scan" {
        scan_bundle_with(Path::new(input), &options, stream)?
    } else {
        scan_raw_with(Path::new(input), &options, stream)?
    };
    write_index(Path::new(output), &index)?;
    print(&summary(&index))
}
fn string_command(command: &str, input: &str, args: &[String]) -> Result<()> {
    let mut options = std::collections::BTreeMap::new();
    let mut bindings = std::collections::BTreeMap::new();
    let mut nodes = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        if flag == "--require-hash" && command != "verify-bindings" {
            if options.insert(flag, "true").is_some() {
                return Err(Error::Invalid("Repeated --require-hash".into()));
            }
            continue;
        }
        let value = args
            .get(i)
            .ok_or_else(|| Error::Invalid(format!("Missing value for {flag}")))?;
        i += 1;
        if flag == "--node-klass" && command == "dictionaries" {
            nodes.push(number(value)?);
        } else if flag == "--bind" {
            let (name, id) = value
                .split_once('=')
                .ok_or_else(|| Error::Invalid("Use --bind CLASS=0xKLASS".into()))?;
            if bindings.insert(name.into(), id.into()).is_some() {
                return Err(Error::Invalid("Duplicate class binding".into()));
            }
        } else {
            let valid = [
                "--boot-profile",
                "--reference-hypothesis",
                "--output",
                "--max-bytes",
            ]
            .contains(&flag)
                || (command == "strings" && flag == "--min-len")
                || (command != "verify-bindings" && flag == "--regex-pack")
                || (command == "verify-bindings" && ["--samples", "--seed"].contains(&flag));
            if !valid || options.insert(flag, value.as_str()).is_some() {
                return Err(Error::Invalid(format!(
                    "Unknown or repeated option: {flag}"
                )));
            }
        }
    }
    let required = |flag| {
        options
            .get(flag)
            .copied()
            .ok_or_else(|| Error::Invalid(format!("Missing {flag}")))
    };
    let num = |flag, default| options.get(flag).map_or(Ok(default), |v| number(v));
    let binding = zgcmaster::raw_strings::Bindings::new(
        required("--boot-profile")?,
        required("--reference-hypothesis")?,
        &bindings,
        num("--max-bytes", zgcmaster::raw_strings::DEFAULT_MAX_BYTES)?,
    )?;
    // Parse/validate everything before creating any output.
    let min_len = num("--min-len", 1)?;
    if command == "dictionaries" && nodes.is_empty() {
        return Err(Error::Invalid(
            "dictionaries needs --node-klass (repeat for each family)".into(),
        ));
    }
    let pack = options
        .get("--regex-pack")
        .map(|p| zgcmaster::patterns::Pack::load(Path::new(p)))
        .transpose()?;
    let samples = num("--samples", 1000)?;
    let seed = num("--seed", 0)?;
    if !(1..=10000).contains(&samples) {
        return Err(Error::Invalid("--samples must be 1..10000".into()));
    }
    let mut file = options
        .get("--output")
        .map(|path| {
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.mode(0o600);
            }
            open.open(path).map(io::BufWriter::new)
        })
        .transpose()?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let out: &mut dyn Write = if let Some(file) = &mut file {
        file
    } else {
        &mut stdout
    };
    if command == "dictionaries" {
        let report = zgcmaster::dictionaries::dictionaries(
            Path::new(input),
            &binding,
            &nodes,
            options.contains_key("--require-hash"),
            pack.as_ref(),
            out,
        )?;
        if file.is_some() {
            print(&report)?;
        }
    } else if command == "strings" {
        let report = zgcmaster::raw_strings::strings_with_pack(
            Path::new(input),
            &binding,
            min_len,
            options.contains_key("--require-hash"),
            pack.as_ref(),
            out,
        )?;
        if file.is_some() {
            print(&report)?;
        }
    } else {
        let report =
            zgcmaster::raw_strings::verify(Path::new(input), &binding, samples as usize, seed)?;
        serde_json::to_writer_pretty(&mut *out, &report)?;
        writeln!(out)?;
        out.flush()?;
        if file.is_some() {
            let mut brief = report;
            brief.as_object_mut().unwrap().remove("samples");
            print(&brief)?;
        }
    }
    Ok(())
}
fn corpus_command(command: &str, inputs: &[&str], args: &[String]) -> Result<()> {
    let mut opts = std::collections::BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        if command == "diff-captures" && flag == "--require-hash" {
            if opts.insert(flag, "true").is_some() {
                return Err(Error::Invalid("Repeated --require-hash".into()));
            }
            continue;
        }
        let value = args
            .get(i)
            .ok_or_else(|| Error::Invalid(format!("Missing value for {flag}")))?;
        i += 1;
        let valid = ["--output", "--max-bytes", "--region-bytes"].contains(&flag)
            || (command == "diff-captures"
                && [
                    "--reference-hypothesis",
                    "--min-len",
                    "--max-unique",
                    "--max-text-bytes",
                    "--regex-pack",
                ]
                .contains(&flag));
        if !valid || opts.insert(flag, value).is_some() {
            return Err(Error::Invalid(format!(
                "Unknown or repeated option: {flag}"
            )));
        }
    }
    let num = |flag, default| opts.get(flag).map_or(Ok(default), |s| number(s));
    let census = zgcmaster::census::Options {
        max_bytes: num("--max-bytes", 1048576)?,
        region_bytes: num("--region-bytes", 67108864)?,
    };
    census.validate()?;
    let diff = if command == "diff-captures" {
        let hypothesis = opts
            .get("--reference-hypothesis")
            .ok_or_else(|| Error::Invalid("diff-captures needs --reference-hypothesis".into()))?;
        let n = num("--max-unique", 250000)?;
        if n > 2000000 {
            return Err(Error::Invalid("--max-unique exceeds 2000000".into()));
        }
        let options = zgcmaster::corpus::Options {
            census,
            reference_hypothesis: (*hypothesis).into(),
            min_len: num("--min-len", 1)?,
            require_hash: opts.contains_key("--require-hash"),
            max_unique: n as usize,
            max_text_bytes: num("--max-text-bytes", 67108864)?,
        };
        options.validate()?;
        Some(options)
    } else {
        None
    };
    let pack = opts
        .get("--regex-pack")
        .map(|p| zgcmaster::patterns::Pack::load(Path::new(p)))
        .transpose()?;
    let mut file = opts
        .get("--output")
        .map(|p| {
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.mode(0o600);
            }
            open.open(p).map(io::BufWriter::new)
        })
        .transpose()?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let out: &mut dyn Write = if let Some(file) = &mut file {
        file
    } else {
        &mut stdout
    };
    let report = if let Some(options) = diff {
        zgcmaster::corpus::diff_captures(
            Path::new(inputs[0]),
            Path::new(inputs[1]),
            Path::new(inputs[2]),
            Path::new(inputs[3]),
            &options,
            pack.as_ref(),
            out,
        )?
    } else {
        let value = zgcmaster::census::census(
            Path::new(inputs[0]),
            load_index(Path::new(inputs[1]))?,
            census,
        )?;
        serde_json::to_writer_pretty(&mut *out, &value)?;
        writeln!(out)?;
        out.flush()?;
        value
    };
    if file.is_some() {
        print(&report)?;
    }
    Ok(())
}
fn run(args: &[String]) -> Result<()> {
    match args {
        [] => {
            write!(io::stdout().lock(), "{HELP}")?;
            Ok(())
        }
        [help] if ["help", "--help", "-h"].contains(&help.as_str()) => {
            write!(io::stdout().lock(), "{HELP}")?;
            Ok(())
        }
        [cmd, input, output, options @ ..] if cmd == "scan" || cmd == "scan-raw" => {
            scan_command(cmd, input, output, options)
        }
        [cmd, input, options @ ..]
            if cmd == "strings" || cmd == "verify-bindings" || cmd == "dictionaries" =>
        {
            string_command(cmd, input, options)
        }
        [cmd, source, index, options @ ..] if cmd == "census" => {
            corpus_command(cmd, &[source, index], options)
        }
        [cmd, a, ia, b, ib, options @ ..] if cmd == "diff-captures" => {
            corpus_command(cmd, &[a, ia, b, ib], options)
        }
        [cmd] if cmd == "profiles" => print(&zgcmaster::profiles::SUPPORTED),
        [cmd, profile] if cmd == "boot-profile" => {
            print(&zgcmaster::profiles::boot(profile, &Default::default())?)
        }
        [cmd, before, after] if cmd == "diff" => print(&zgcmaster::analysis::diff(
            &load_index(Path::new(before))?,
            &load_index(Path::new(after))?,
        )?),
        [cmd, source, path, directory] if cmd == "carve" => {
            Reader::open(Path::new(source), load_index(Path::new(path))?)?
                .carve(Path::new(directory), io::stdout().lock())
        }
        [cmd, path] if cmd == "summary" => print(&summary(&load_index(Path::new(path))?)),
        [cmd, path, filter @ ..] if cmd == "list" && filter.len() <= 1 => {
            let index = load_index(Path::new(path))?;
            if index.streamed {
                return Err(Error::Invalid(
                    "Streaming summary: read the JSONL file, or build a filtered index".into(),
                ));
            }
            if index.layout.is_none() {
                return Err(Error::Invalid(
                    "Raw-only mode has header groups, not identified objects; use summary".into(),
                ));
            }
            for object in &index.objects {
                if filter
                    .first()
                    .is_none_or(|s| index.class_name(object).contains(s))
                {
                    line(&index.object_view(object))?;
                }
            }
            Ok(())
        }
        [cmd, bundle, path, offset] if cmd == "show" => {
            let mut reader = Reader::open(Path::new(bundle), load_index(Path::new(path))?)?;
            print(&reader.show(number(offset)?)?)
        }
        [cmd, bundle, path, class_filter] if cmd == "dump" => {
            let mut reader = Reader::open(Path::new(bundle), load_index(Path::new(path))?)?;
            let offsets: Vec<_> = reader
                .index
                .objects
                .iter()
                .filter(|o| reader.index.class_name(o).contains(class_filter))
                .map(|o| o.offset)
                .collect();
            for offset in offsets {
                line(&reader.show(offset)?)?;
            }
            Ok(())
        }
        [cmd, bundle, path, offset, output] if cmd == "extract" => {
            let mut reader = Reader::open(Path::new(bundle), load_index(Path::new(path))?)?;
            print(&reader.extract(number(offset)?, Path::new(output))?)
        }
        _ => Err(Error::Invalid(format!("Invalid arguments.\n{HELP}"))),
    }
}
fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(Error::Json(error)) if error.io_error_kind() == Some(io::ErrorKind::BrokenPipe) => {
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", json!({"error": error.to_string()}));
            ExitCode::FAILURE
        }
    }
}
