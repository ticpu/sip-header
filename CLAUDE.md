## Project Type

Library crate for SIP header field value parsing. Sits between `sip-uri`
(addr-spec/name-addr) and full SIP stacks. Covers RFC 3261 header grammar
and extensions. `Cargo.lock` is gitignored per Cargo convention for libraries.

## RFC Compliance Is Non-Negotiable

This crate parses SIP header field values per the RFCs. Every parser must
follow the grammar from its defining RFC. If a real-world SIP implementation
sends non-conformant data, we can accept it permissively **only if**:

1. A comment cites the RFC section being relaxed
2. The relaxation is clearly bounded (not open-ended leniency)
3. A test proves the non-conformant input is accepted

Never invent syntax. Never guess at encoding. If an RFC doesn't define
behavior for a given input, return `Err`.

## No FreeSWITCH Coupling

This crate has **zero FreeSWITCH knowledge**. No references to FreeSWITCH,
mod_sofia, ESL, ARRAY encoding, `sip_i_*` variables, or any FS-specific
concepts in source code, doc comments, error messages, or tests.

FreeSWITCH integration (ARRAY decoding, bracket stripping, channel
variable mapping) belongs in `freeswitch-types`, which re-exports this
crate. If you're tempted to add FS-specific logic here, it belongs there.

## No PII or Organization-Specific Data

**NEVER** include real phone numbers, real hostnames, organization names,
internal URLs, or any other PII in source code, tests, or documentation.
Use RFC-compliant test values only:

- Phone numbers: `+1555xxxxxxx` (555 prefix)
- IPv4: `198.51.100.x` or `203.0.113.x` (RFC 5737 TEST-NET)
- Domains: `example.com`, `example.org`, `example.net` (RFC 6761)
- IPv6: `2001:db8::x` (RFC 3849 documentation prefix)
- Organization names: "EXAMPLE CO", generic descriptions
- URN identifiers: synthetic hashes, `TEST` prefixes

The pre-commit hook runs gitleaks to enforce this.

## `#[non_exhaustive]` Policy

All public enums and public-field structs get `#[non_exhaustive]`.
Single-field error newtypes (`pub struct ParseFooError(pub String)`) are
exempt.

## SipHeader Enum — IANA Registry Sync

The `SipHeader` enum covers all registered SIP header field names from
the IANA registry. The pre-commit hook runs `hooks/check-sip-headers.sh`
to verify the enum matches `iana-sip-headers.txt`.

**When IANA registers new SIP headers:**

1. Add the header name to `iana-sip-headers.txt` (alphabetical order)
2. Add the variant to `SipHeader` in `src/header.rs`
3. The check script validates the sync

Not every `SipHeader` variant needs a typed parser on `SipHeaderLookup`.
Only headers with structured values (name-addr, comma-separated entries,
etc.) get typed accessor methods. Simple string headers are accessed via
`sip_header(SipHeader::Foo)` returning `Option<&str>`.

## API Boundary Rules

- **`sip-uri` is the only accepted public dependency.** The `pub use sip_uri;`
  re-export and `SipHeaderAddr` returning `sip_uri::Uri` are intentional
  (same author, narrow scope, stable).
- **Never expose other dependency types in public signatures.** Wrap them
  or return `impl Trait`.
- **`FromStr` uses `eq_ignore_ascii_case`** for case-insensitive matching.
  `Display` always emits the canonical wire form from the IANA registry.

## Build & Test

```sh
cargo fmt --all
cargo check --message-format=short
cargo check --features serde --message-format=short
cargo check --features conference-info --message-format=short
cargo clippy --fix --allow-dirty --message-format=short
cargo test --lib
```

The pre-commit hook enforces: formatting, clippy, `-D missing_docs`,
broken intra-doc links, all tests (including doctests), IANA sync, and
gitleaks.

## Library Code Rules

**No `assert!`/`panic!`/`unwrap()` in library code** outside of tests.
Return `Result` or `Option` instead.

**Correctness over recovery.** Never silently absorb parse errors. If a
header value doesn't conform to the RFC grammar, return `Err`. Never use
`.parse().ok()` to collapse parse failures into `None` where they become
indistinguishable from absent headers.

## Release Workflow

### Pre-release checks

```sh
cargo fmt --all
cargo clippy --release -- -D warnings
cargo test --release
cargo build --release
cargo semver-checks check-release
cargo publish --dry-run
```

### Publish

**Never `cargo publish` without completing these steps first:**

1. Create signed annotated tags (`git tag -as`)
2. Push the tags (`git push --tags`)
3. Wait for CI to pass on the tagged commit
4. Only then `cargo publish`

## Documentation Style

All public items must have doc comments. Brief one-liners are fine for
self-evident items.

Doc comments on `SipHeader` variants: include the canonical wire name
in backticks and the RFC reference for well-known headers. For obscure
headers, just the wire name suffices.

**No hardcoded counts in prose.** Don't write "134 headers" in markdown
or comments. Use CI-generated badges or just omit the count.

## Development Methodology — TDD

1. Write failing tests that specify the new behavior
2. Confirm tests fail (`cargo test --lib`)
3. `cargo fmt && git commit --no-verify` (red phase)
4. Implement the fix/feature
5. Confirm all tests pass
6. Commit the implementation (hooks run normally)
