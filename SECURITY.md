# Security and sensitive data

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/clintonkavai/zgcmaster/security/advisories/new)
for suspected vulnerabilities. Include affected revision, command, platform,
impact, and a synthetic reproduction. Do not include credentials, real heap
captures, recovered strings, or customer data, even in a private report unless
a maintainer has explicitly agreed on a secure handling process.

If private reporting is unavailable, open a public issue requesting a private
contact without disclosing exploit details or sensitive data. This is a
volunteer-maintained experimental project; no response-time SLA is promised.
Only the latest `main` revision is currently maintained; there are no LTS branches.

## Capture handling

Analyze only data you are authorized to access. A heap can contain passwords,
session tokens, personal data, private keys and executable payloads. Capture
checksums and derived reports can also be sensitive identifiers. Never upload
real captures or decoded output to issues, pull requests, Actions artifacts, or
third-party analyzers without separate authorization.

Use immutable copies, read-only mounts and least-privileged containers. The CLI
Compose service has no network and a 512 MiB memory limit. Output disk consumption
can still be large. Do not execute or open carved payloads with privileged tools.
The reader performs bounded structural checks, not full validation of extracted
file formats, proof of liveness, or a malware safety assessment.

`strings --output` and `verify-bindings --output` create mode-0600 files on Unix.
Other output commands and shell redirections may use your umask; use `umask 077`
and a private output directory when handling sensitive data. Output is never
overwritten. Incomplete streams lack the completion footer and must be discarded
or retained only as explicitly partial evidence.

## Development and CI

The fixture is synthetic, binds to localhost and is not a production service.
It intentionally exposes inspection endpoints and uses Java instrumentation and
`Unsafe` in the fixture only. The CLI contains no unsafe Rust. Do not deploy the
fixture publicly or connect it to production credentials/agents during tests.

CI runs synthetic/generated fixtures only. It does not upload heap files,
extracted payloads, string JSONL, maps, or process environments. The public-tree
check is a guardrail, not a guarantee that every possible secret will be detected.
