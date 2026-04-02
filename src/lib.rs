//! SIP header field parsers for standard RFC types.
//!
//! This crate provides parsers for SIP header values as defined in RFC 3261
//! and extensions. It sits between URI parsing ([`sip_uri`]) and full SIP
//! stacks, handling the header-level grammar: display names, header parameters,
//! and structured header values.
//!
//! # Modules
//!
//! - [`header_addr`] — RFC 3261 `name-addr` with header-level parameters
//! - [`header`] — SIP header name catalog and [`SipHeaderLookup`] trait
//! - [`message`] — Extract headers and Request-URI from raw SIP message text (feature: `message`)
//! - [`via`] — RFC 3261 Via header parser
//! - [`warning`] — RFC 3261 Warning header parser
//! - [`auth`] — SIP authentication value parser (Authorization, WWW-Authenticate, etc.)
//! - [`contact`] — RFC 3261 Contact header parser
//! - [`accept`] — RFC 3261 Accept header parser
//! - [`accept_encoding`] — RFC 3261 Accept-Encoding header parser
//! - [`accept_language`] — RFC 3261 Accept-Language header parser
//! - [`security`] — RFC 3329 Security mechanism parser
//! - [`uri_info`] — `<absoluteURI> *(SEMI generic-param)` parser (Call-Info, Alert-Info, Error-Info)
//! - [`history_info`] — RFC 7044 History-Info header parser
//! - [`geolocation`] — RFC 6442 Geolocation header parser
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

/// Unescape RFC 3261 §25.1 `quoted-pair` sequences: `\"` → `"`, `\\` → `\`.
///
/// Operates on the content *between* surrounding double-quotes (caller strips
/// them). Skips allocation when no backslash escapes are present.
pub(crate) fn unescape_quoted_pair(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            result.push(ch);
        }
    }
    result
}

/// Escape a string for use inside a `quoted-string` (RFC 3261 §25.1).
///
/// Escapes `"` → `\"` and `\` → `\\`. Does **not** add surrounding quotes.
pub(crate) fn escape_quoted_pair(s: &str) -> String {
    if !s.contains(['"', '\\']) {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        if ch == '"' || ch == '\\' {
            result.push('\\');
        }
        result.push(ch);
    }
    result
}

/// Write a `quoted-string` to a formatter: surrounds with `"` and escapes
/// embedded quotes/backslashes per RFC 3261 §25.1.
pub(crate) fn write_quoted_pair(f: &mut std::fmt::Formatter<'_>, value: &str) -> std::fmt::Result {
    f.write_str("\"")?;
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            write!(f, "\\{ch}")?;
        } else {
            write!(f, "{ch}")?;
        }
    }
    f.write_str("\"")
}

/// Split comma-separated header entries respecting angle-bracket nesting
/// and double-quoted strings.
///
/// SIP headers that carry lists (RFC 3261 §7.3.1) use commas as delimiters,
/// but commas may also appear inside angle-bracketed URIs or quoted strings
/// (e.g. Warning warn-text per §20.43). This function splits only on commas
/// at bracket depth zero and outside quoted strings.
///
/// Backslash escapes inside quoted strings (RFC 3261 §25.1 `quoted-pair`)
/// are respected to avoid premature quote-close on `\"`.
pub fn split_comma_entries(raw: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut depth = 0u32;
    let mut in_quotes = false;
    let mut prev_backslash = false;
    let mut start = 0;

    for (i, ch) in raw.char_indices() {
        if prev_backslash {
            prev_backslash = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => prev_backslash = true,
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => depth += 1,
            '>' if !in_quotes => depth = depth.saturating_sub(1),
            ',' if depth == 0 && !in_quotes => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_comma_simple() {
        assert_eq!(split_comma_entries("a, b, c"), vec!["a", " b", " c"]);
    }

    #[test]
    fn split_comma_respects_angle_brackets() {
        let input = "<sip:a@host,x>, <sip:b@host>";
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("host,x"));
    }

    #[test]
    fn split_comma_respects_quoted_strings() {
        let input = r#"301 example.com "text, comma", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("text, comma"));
    }

    #[test]
    fn split_comma_respects_escaped_quote() {
        let input = r#"301 example.com "say \"hi, there\"", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
    }
}
