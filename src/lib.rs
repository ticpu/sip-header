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
//! - [`message`] — Extract headers and Request-URI from raw SIP message text (feature: `message`)
//! - [`uri_info`] — `<absoluteURI> *(SEMI generic-param)` parser (Call-Info, Alert-Info, Error-Info)
//! - [`history_info`] — RFC 7044 History-Info header parser
//! - [`geolocation`] — RFC 6442 Geolocation header parser
//! - [`auth`] — SIP authentication value parser (Authorization, WWW-Authenticate, etc.)
//! - [`warning`] — RFC 3261 Warning header parser
//! - [`via`] — RFC 3261 Via header parser
//! - `conference_info` — RFC 4575 conference event package (feature: `conference-info`)

#[macro_use]
mod macros;

pub use sip_uri;

pub mod accept;
pub mod accept_encoding;
pub mod accept_language;
pub mod auth;
#[cfg(feature = "conference-info")]
pub mod conference_info;
pub mod contact;
pub mod geolocation;
pub mod header;
pub mod header_addr;
pub mod history_info;
#[cfg(feature = "message")]
pub mod message;
pub mod security;
pub mod uri_info;
pub mod via;
pub mod warning;

pub use accept::{SipAccept, SipAcceptEntry, SipAcceptError};
pub use accept_encoding::{SipAcceptEncoding, SipAcceptEncodingEntry, SipAcceptEncodingError};
pub use accept_language::{SipAcceptLanguage, SipAcceptLanguageEntry, SipAcceptLanguageError};
pub use auth::{SipAuthError, SipAuthValue};
pub use contact::ContactValue;
pub use geolocation::{SipGeolocation, SipGeolocationRef};
pub use header::{ParseSipHeaderError, SipHeader, SipHeaderLookup};
pub use header_addr::{ParseSipHeaderAddrError, SipHeaderAddr};
pub use history_info::{HistoryInfo, HistoryInfoEntry, HistoryInfoError, HistoryInfoReason};
#[cfg(feature = "message")]
pub use message::{extract_header, extract_request_uri};
pub use security::{SipSecurity, SipSecurityError, SipSecurityMechanism};
pub use uri_info::{UriInfo, UriInfoEntry, UriInfoError};
pub use via::{SipVia, SipViaEntry, SipViaError};
pub use warning::{SipWarning, SipWarningEntry, SipWarningError};

/// Format a slice of displayable items as a separated list.
pub(crate) fn fmt_joined<T: std::fmt::Display>(
    f: &mut std::fmt::Formatter<'_>,
    items: &[T],
    separator: &str,
) -> std::fmt::Result {
    for (i, item) in items
        .iter()
        .enumerate()
    {
        if i > 0 {
            f.write_str(separator)?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

/// Split comma-separated header entries respecting angle-bracket nesting.
///
/// SIP headers that carry lists (RFC 3261 §7.3.1) use commas as delimiters,
/// but commas may also appear inside angle-bracketed URIs. This function
/// splits only on commas at bracket depth zero.
pub fn split_comma_entries(raw: &str) -> Vec<&str> {
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
