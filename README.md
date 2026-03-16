# sip-header

SIP header field parsers for Rust. RFC 3261 name-addr, Call-Info,
History-Info (RFC 7044), Geolocation (RFC 6442), and conference-info
(RFC 4575).

[![CI](https://github.com/ticpu/sip-header/actions/workflows/ci.yml/badge.svg)](https://github.com/ticpu/sip-header/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sip-header.svg)](https://crates.io/crates/sip-header)
[![docs.rs](https://docs.rs/sip-header/badge.svg)](https://docs.rs/sip-header)

Sits between URI parsing ([sip-uri](https://crates.io/crates/sip-uri))
and full SIP stacks, handling the header-level grammar: display names,
header parameters, and structured header values.

```toml
[dependencies]
sip-header = "0.1"
```

## SipHeaderAddr — RFC 3261 name-addr

Parses `[display-name] <URI> ;param=value` with header-level parameters
(tag, expires, etc.):

```rust
use sip_header::SipHeaderAddr;

let addr: SipHeaderAddr = r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>;tag=abc123"#
    .parse().unwrap();
assert_eq!(addr.display_name(), Some("EXAMPLE CO"));
assert_eq!(addr.tag(), Some("abc123"));
assert_eq!(addr.sip_uri().unwrap().user(), Some("+15551234567"));
```

## SipCallInfo — RFC 3261 §20.9

Parses Call-Info headers with URI + parameter entries:

```rust
use sip_header::SipCallInfo;

let raw = "<urn:emergency:uid:callid:abc:bcf.example.com>;purpose=emergency-CallId,\
           <https://adr.example.com/info>;purpose=EmergencyCallData.ProviderInfo";
let ci = SipCallInfo::parse(raw).unwrap();
assert_eq!(ci.len(), 2);
assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
```

## HistoryInfo — RFC 7044

Parses History-Info routing chains with embedded RFC 3326 Reason headers:

```rust
use sip_header::HistoryInfo;

let raw = "<sip:alice@esrp.example.com>;index=1,\
           <sip:sos@psap.example.com>;index=1.1";
let hi = HistoryInfo::parse(raw).unwrap();
assert_eq!(hi.len(), 2);
assert_eq!(hi.entries()[0].index(), Some("1"));
```

## SipHeaderLookup trait

Typed accessors for any key-value store holding SIP headers:

```rust
use std::collections::HashMap;
use sip_header::SipHeaderLookup;

let mut headers = HashMap::new();
headers.insert(
    "Call-Info".to_string(),
    "<urn:example:test>;purpose=icon".to_string(),
);
let ci = headers.call_info().unwrap().unwrap();
assert_eq!(ci.entries()[0].purpose(), Some("icon"));
```

## SipHeader enum — full IANA registry

The `SipHeader` enum covers all registered SIP header field names from
the [IANA SIP Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-2)
registry. Use it for typed lookups, or fall back to `sip_header_str()`
for unregistered headers.

## Modules

| Module | Description |
|---|---|
| `header_addr` | RFC 3261 `name-addr` with header-level parameters |
| `header` | `SipHeader` enum, `SipHeaderLookup` trait |
| `message` | Extract headers from raw SIP message text |
| `call_info` | RFC 3261 §20.9 Call-Info parser |
| `history_info` | RFC 7044 History-Info with RFC 3326 Reason |
| `geolocation` | RFC 6442 Geolocation header |
| `conference_info` | RFC 4575 conference event XML (feature: `conference-info`) |

## Features

| Feature | Dependencies | Description |
|---|---|---|
| `serde` | serde | Serde derives on all types |
| `conference-info` | quick-xml, serde | RFC 4575 XML parsing |

## Ecosystem

This crate is part of a Rust SIP/NG9-1-1 ecosystem:

- [sip-uri](https://crates.io/crates/sip-uri) — RFC 3261/3966/8141 URI parser
- **sip-header** — SIP header field parsers (this crate)
- [eido](https://crates.io/crates/eido) — NENA NG9-1-1 emergency data types
- [freeswitch-types](https://crates.io/crates/freeswitch-types) — FreeSWITCH ESL protocol types (re-exports sip-header)

## RFC coverage

- **RFC 3261** — SIP name-addr, Call-Info, core header catalog
- **RFC 3325** — P-Asserted-Identity, P-Preferred-Identity
- **RFC 3326** — Reason header (embedded in History-Info)
- **RFC 4575** — Conference event package XML (feature-gated)
- **RFC 6442** — Geolocation header
- **RFC 7044** — History-Info header

## Development

```sh
cargo fmt --all
cargo clippy --message-format=short
RUSTDOCFLAGS="-D missing_docs -D rustdoc::broken_intra_doc_links" cargo doc --no-deps
cargo test
```

The pre-commit hook validates the `SipHeader` enum against the IANA
registry (`iana-sip-headers.txt`).

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
