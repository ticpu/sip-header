//! SIP Contact header value parser (RFC 3261 §20.10).
//!
//! Contact can be either `*` (wildcard, used in REGISTER with Expires: 0)
//! or a comma-separated list of `name-addr / addr-spec` entries with
//! optional parameters.

use crate::header_addr::{ParseSipHeaderAddrError, SipHeaderAddr};
use std::fmt;

/// A single Contact header value: either the `*` wildcard or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContactValue {
    /// The `*` wildcard (RFC 3261 §10.2.2, used in REGISTER).
    Wildcard,
    /// A `name-addr` or `addr-spec` with optional contact parameters.
    Addr(Box<SipHeaderAddr>),
}

impl fmt::Display for ContactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => f.write_str("*"),
            Self::Addr(addr) => write!(f, "{addr}"),
        }
    }
}

/// Parse a single contact entry (after comma-splitting).
fn parse_contact_entry(raw: &str) -> Result<ContactValue, ParseSipHeaderAddrError> {
    let trimmed = raw.trim();
    if trimmed == "*" {
        Ok(ContactValue::Wildcard)
    } else {
        trimmed
            .parse::<SipHeaderAddr>()
            .map(|a| ContactValue::Addr(Box::new(a)))
    }
}

/// Parse a comma-separated Contact header value into a list of [`ContactValue`].
pub fn parse_contact_list(raw: &str) -> Result<Vec<ContactValue>, ParseSipHeaderAddrError> {
    let trimmed = raw.trim();
    if trimmed == "*" {
        return Ok(vec![ContactValue::Wildcard]);
    }
    crate::split_comma_entries(trimmed)
        .into_iter()
        .map(parse_contact_entry)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard() {
        let contacts = parse_contact_list("*").unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(matches!(contacts[0], ContactValue::Wildcard));
    }

    #[test]
    fn single_addr() {
        let contacts = parse_contact_list("<sip:alice@198.51.100.1>").unwrap();
        assert_eq!(contacts.len(), 1);
        match &contacts[0] {
            ContactValue::Addr(addr) => {
                assert!(addr
                    .uri()
                    .to_string()
                    .contains("alice"));
            }
            _ => panic!("expected Addr"),
        }
    }

    #[test]
    fn multiple_addrs() {
        let contacts =
            parse_contact_list("<sip:alice@198.51.100.1>, \"Bob\" <sip:bob@198.51.100.2>").unwrap();
        assert_eq!(contacts.len(), 2);
        match &contacts[1] {
            ContactValue::Addr(addr) => {
                assert_eq!(addr.display_name(), Some("Bob"));
            }
            _ => panic!("expected Addr"),
        }
    }

    #[test]
    fn display_wildcard() {
        assert_eq!(ContactValue::Wildcard.to_string(), "*");
    }

    #[test]
    fn display_addr() {
        let addr = "sip:alice@198.51.100.1"
            .parse::<sip_uri::Uri>()
            .unwrap();
        let cv = ContactValue::Addr(Box::new(SipHeaderAddr::new(addr)));
        assert!(cv
            .to_string()
            .contains("alice"));
    }
}
