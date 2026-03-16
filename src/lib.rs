//! SIP header field parsers for standard RFC types.
//!
//! This crate provides parsers for SIP header values as defined in RFC 3261
//! and extensions. It sits between URI parsing ([`sip_uri`]) and full SIP
//! stacks, handling the header-level grammar: display names, header parameters,
//! and structured header values like Call-Info and History-Info.
//!
//! # Modules
//!
//! - [`header_addr`] — RFC 3261 `name-addr` with header-level parameters
//! - [`header`] — SIP header name catalog and [`SipHeaderLookup`] trait
//! - [`message`] — Extract headers from raw SIP message text
//! - [`call_info`] — RFC 3261 §20.9 Call-Info header parser
//! - [`history_info`] — RFC 7044 History-Info header parser
//! - [`geolocation`] — RFC 6442 Geolocation header parser
//! - `conference_info` — RFC 4575 conference event package (feature: `conference-info`)

#[macro_use]
mod macros;

pub use sip_uri;

pub mod call_info;
#[cfg(feature = "conference-info")]
pub mod conference_info;
pub mod geolocation;
pub mod header;
pub mod header_addr;
pub mod history_info;
pub mod message;

pub use call_info::{SipCallInfo, SipCallInfoEntry, SipCallInfoError};
pub use geolocation::{SipGeolocation, SipGeolocationRef};
pub use header::{ParseSipHeaderError, SipHeader, SipHeaderLookup};
pub use header_addr::{ParseSipHeaderAddrError, SipHeaderAddr};
pub use history_info::{HistoryInfo, HistoryInfoEntry, HistoryInfoError, HistoryInfoReason};
pub use message::extract_header;

/// Split comma-separated entries respecting angle-bracket nesting.
pub(crate) fn split_comma_entries(raw: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;

    for (i, ch) in raw.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                entries.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < raw.len() {
        entries.push(&raw[start..]);
    }

    entries
}
