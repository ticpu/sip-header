//! SIP Via header parser (RFC 3261 §20.42).

use std::fmt;

/// Error parsing a SIP Via header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipViaError {
    /// The Via header value is empty.
    Empty,
    /// The Via header value has an invalid format.
    InvalidFormat(String),
}

impl fmt::Display for SipViaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Via header is empty"),
            Self::InvalidFormat(msg) => write!(f, "Invalid Via format: {}", msg),
        }
    }
}

impl std::error::Error for SipViaError {}

/// A single Via entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipViaEntry {
    protocol_name: String,
    protocol_version: String,
    transport: String,
    host: String,
    port: Option<u16>,
    params: Vec<(String, Option<String>)>,
    rport: Option<Option<u16>>,
}

impl SipViaEntry {
    /// Returns the protocol name (e.g., "SIP").
    pub fn protocol(&self) -> &str {
        &self.protocol_name
    }

    /// Returns the protocol version (e.g., "2.0").
    pub fn version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns the transport protocol (e.g., "UDP", "TCP", "TLS").
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Returns the host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port, if present.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns all parameters.
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Returns a specific parameter value by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
            .map(|(_, v)| v.as_deref())
    }

    /// Returns the `branch` parameter value, if present.
    pub fn branch(&self) -> Option<&str> {
        self.param("branch")
            .flatten()
    }

    /// Returns the `received` parameter value, if present.
    pub fn received(&self) -> Option<&str> {
        self.param("received")
            .flatten()
    }

    /// Returns the `rport` parameter.
    ///
    /// - `None` if the parameter is absent
    /// - `Some(None)` if present without a value
    /// - `Some(Some(port))` if present with a value
    ///
    /// Invalid rport values are rejected at parse time, so this accessor
    /// is infallible.
    pub fn rport(&self) -> Option<Option<u16>> {
        self.rport
    }

    fn parse(entry: &str) -> Result<Self, SipViaError> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(SipViaError::InvalidFormat("empty Via entry".to_string()));
        }

        // Split on first semicolon to separate sent-protocol/sent-by from params
        let (main_part, params_part) = if let Some(semi_idx) = trimmed.find(';') {
            (&trimmed[..semi_idx], Some(&trimmed[semi_idx + 1..]))
        } else {
            (trimmed, None)
        };

        let (protocol_name, protocol_version, transport, sent_by) = parse_sent_protocol(main_part)?;
        let (host, port) = parse_host_port(sent_by)?;

        let params: Vec<(String, Option<String>)> = crate::parse_params(params_part.unwrap_or(""))
            .into_iter()
            .map(|p| {
                (
                    p.key
                        .to_ascii_lowercase(),
                    p.value
                        .map(str::to_string),
                )
            })
            .collect();

        let rport = params
            .iter()
            .find(|(k, _)| k == "rport")
            .map(|(_, v)| match v {
                None => Ok(None),
                Some(s) => s
                    .parse::<u16>()
                    .map(Some)
                    .map_err(|_| SipViaError::InvalidFormat("invalid rport value".to_string())),
            })
            .transpose()?;

        Ok(Self {
            protocol_name,
            protocol_version,
            transport,
            host,
            port,
            params,
            rport,
        })
    }
}

/// Split `sent-protocol LWS sent-by` into its parts, allowing SWS around
/// each `/` (RFC 3261 §25.1 `SLASH`).
fn parse_sent_protocol(main: &str) -> Result<(String, String, String, &str), SipViaError> {
    let malformed =
        || SipViaError::InvalidFormat("expected 'protocol/version/transport host[:port]'".into());
    let (name_raw, rest) = main
        .split_once('/')
        .ok_or_else(malformed)?;
    let (version_raw, after_slash) = rest
        .split_once('/')
        .ok_or_else(malformed)?;
    let (name, version) = (name_raw.trim(), version_raw.trim());
    let rest = after_slash.trim_start();
    let (mut transport, mut sent_by) = rest.split_at(
        rest.find(char::is_whitespace)
            .unwrap_or(rest.len()),
    );
    sent_by = sent_by.trim();
    // RFC 3261 §25.1 transport is a non-empty token; an empty one directly
    // before sent-by (`SIP/2.0/ host`) stays accepted.
    if sent_by.is_empty()
        && after_slash.starts_with(char::is_whitespace)
        && name == name_raw
        && version == version_raw
    {
        (transport, sent_by) = ("", transport);
    }
    if sent_by.is_empty()
        || [name, version, transport]
            .iter()
            .any(|p| p.contains(|c: char| c == '/' || c.is_whitespace()))
    {
        return Err(malformed());
    }
    Ok((name.into(), version.into(), transport.into(), sent_by))
}

impl fmt::Display for SipViaEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.protocol_name, self.protocol_version, self.transport
        )?;

        // Handle IPv6 addresses with brackets
        if self
            .host
            .contains(':')
            && !self
                .host
                .starts_with('[')
        {
            write!(f, " [{}]", self.host)?;
        } else {
            write!(f, " {}", self.host)?;
        }

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        for (key, value) in &self.params {
            crate::write_param(f, key, value.as_deref(), false)?;
        }

        Ok(())
    }
}

/// Parsed SIP Via header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipVia {
    entries: Vec<SipViaEntry>,
}

impl SipVia {
    /// Parses a Via header value.
    pub fn parse(raw: &str) -> Result<Self, SipViaError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SipViaError::Empty);
        }
        Self::from_entries(crate::split_comma_entries(raw))
    }

    /// Build from entries a transport already split; each is one `via-parm`.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, SipViaError> {
        let entries = entries
            .into_iter()
            .map(SipViaEntry::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if entries.is_empty() {
            return Err(SipViaError::Empty);
        }
        Ok(Self { entries })
    }

    /// Returns the Via entries.
    pub fn entries(&self) -> &[SipViaEntry] {
        &self.entries
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipViaEntry> {
        self.entries
    }

    /// Returns the number of Via entries.
    pub fn len(&self) -> usize {
        self.entries
            .len()
    }

    /// Returns `true` if there are no Via entries.
    pub fn is_empty(&self) -> bool {
        self.entries
            .is_empty()
    }
}

impl fmt::Display for SipVia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.entries, ", ")
    }
}

impl_from_str_via_parse!(SipVia, SipViaError);

impl IntoIterator for SipVia {
    type Item = SipViaEntry;
    type IntoIter = std::vec::IntoIter<SipViaEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .into_iter()
    }
}

impl<'a> IntoIterator for &'a SipVia {
    type Item = &'a SipViaEntry;
    type IntoIter = std::slice::Iter<'a, SipViaEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .iter()
    }
}

/// Split `sent-by = host [ COLON port ]`, allowing SWS around the colon.
fn parse_host_port(sent_by: &str) -> Result<(String, Option<u16>), SipViaError> {
    let invalid = |msg: &str| SipViaError::InvalidFormat(msg.to_string());
    let (host, port) = if let Some(inner) = sent_by.strip_prefix('[') {
        let close = inner
            .find(']')
            .ok_or_else(|| invalid("unclosed IPv6 bracket"))?;
        let rest = inner[close + 1..].trim_start();
        let port = if rest.is_empty() {
            None
        } else {
            Some(
                rest.strip_prefix(':')
                    .ok_or_else(|| invalid("unexpected characters after IPv6 reference"))?,
            )
        };
        (&inner[..close], port)
    } else {
        match sent_by.split_once(':') {
            Some((_, port)) if port.contains(':') => {
                return Err(invalid("IPv6 sent-by must be bracketed"));
            }
            Some((host, port)) => (host.trim_end(), Some(port)),
            None => (sent_by, None),
        }
    };
    if host.contains(char::is_whitespace) {
        return Err(invalid("whitespace inside sent-by host"));
    }
    let port = port
        .map(|p| {
            p.trim_start()
                .parse::<u16>()
                .map_err(|_| {
                    SipViaError::InvalidFormat(format!("invalid port ({} bytes)", p.len()))
                })
        })
        .transpose()?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_via() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060").unwrap();
        assert_eq!(via.len(), 1);

        let entry = &via.entries()[0];
        assert_eq!(entry.protocol(), "SIP");
        assert_eq!(entry.version(), "2.0");
        assert_eq!(entry.transport(), "UDP");
        assert_eq!(entry.host(), "198.51.100.1");
        assert_eq!(entry.port(), Some(5060));
        assert!(entry
            .params()
            .is_empty());
    }

    #[test]
    fn test_multiple_vias() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        assert_eq!(via.len(), 2);

        let entry1 = &via.entries()[0];
        assert_eq!(entry1.host(), "198.51.100.1");
        assert_eq!(entry1.port(), Some(5060));
        assert_eq!(entry1.transport(), "UDP");

        let entry2 = &via.entries()[1];
        assert_eq!(entry2.host(), "203.0.113.5");
        assert_eq!(entry2.port(), None);
        assert_eq!(entry2.transport(), "TCP");
    }

    #[test]
    fn test_via_with_params() {
        let via = SipVia::parse(
            "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKnashds8;received=203.0.113.10;rport=5061",
        )
        .unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.branch(), Some("z9hG4bKnashds8"));
        assert_eq!(entry.received(), Some("203.0.113.10"));
        assert_eq!(entry.rport(), Some(Some(5061)));
    }

    #[test]
    fn test_via_with_rport_no_value() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060;rport").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.rport(), Some(None));
    }

    #[test]
    fn test_via_without_rport() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.rport(), None);
    }

    #[test]
    fn test_via_ipv6() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]:5060").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), "2001:db8::1");
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn test_via_ipv6_no_port() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), "2001:db8::1");
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn test_via_hostname() {
        let via = SipVia::parse("SIP/2.0/TLS example.com:5061").unwrap();

        let entry = &via.entries()[0];
        assert_eq!(entry.host(), "example.com");
        assert_eq!(entry.port(), Some(5061));
        assert_eq!(entry.transport(), "TLS");
    }

    #[test]
    fn test_empty_via() {
        let result = SipVia::parse("");
        assert!(matches!(result, Err(SipViaError::Empty)));
    }

    #[test]
    fn test_empty_via_whitespace() {
        let result = SipVia::parse("   ");
        assert!(matches!(result, Err(SipViaError::Empty)));
    }

    #[test]
    fn test_invalid_format() {
        let result = SipVia::parse("invalid");
        assert!(matches!(result, Err(SipViaError::InvalidFormat(_))));
    }

    #[test]
    fn test_rport_invalid_value_is_error() {
        let result = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060;rport=garbage");
        assert!(result.is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        let original =
            "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKnashds8;received=203.0.113.10;rport";
        let via = SipVia::parse(original).unwrap();
        let displayed = via.to_string();

        let reparsed = SipVia::parse(&displayed).unwrap();
        assert_eq!(via, reparsed);
    }

    #[test]
    fn test_display_multiple_vias() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        let displayed = via.to_string();
        assert!(displayed.contains("198.51.100.1"));
        assert!(displayed.contains("203.0.113.5"));
    }

    #[test]
    fn test_into_iterator() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();

        let mut count = 0;
        for entry in &via {
            assert!(entry.host() == "198.51.100.1" || entry.host() == "203.0.113.5");
            count += 1;
        }
        assert_eq!(count, 2);

        let entries: Vec<_> = via
            .into_iter()
            .collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_into_entries() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060, SIP/2.0/TCP 203.0.113.5").unwrap();
        let entries = via.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].host(), "198.51.100.1");
        assert_eq!(entries[1].host(), "203.0.113.5");
    }

    #[test]
    fn test_from_str() {
        let via: SipVia = "SIP/2.0/UDP 198.51.100.1:5060"
            .parse()
            .unwrap();
        assert_eq!(via.len(), 1);
    }

    #[test]
    fn test_param_case_insensitive() {
        let via = SipVia::parse("SIP/2.0/UDP 198.51.100.1:5060;Branch=test").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.param("branch"), Some(Some("test")));
        assert_eq!(entry.param("BRANCH"), Some(Some("test")));
    }

    #[test]
    fn test_display_ipv6() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1]:5060").unwrap();
        let displayed = via.to_string();
        assert!(displayed.contains("[2001:db8::1]"));
    }

    #[test]
    fn from_entries_matches_parse() {
        let a = "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1";
        let b = "SIP/2.0/TCP 203.0.113.5";
        let split = SipVia::from_entries([a, b]).unwrap();
        let joined = SipVia::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
        assert_eq!(split.to_string(), format!("{a}, {b}"));
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert!(matches!(
            SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1", "invalid"]),
            Err(SipViaError::InvalidFormat(_))
        ));
    }

    #[test]
    fn sws_around_protocol_slashes() {
        let via = SipVia::parse("SIP / 2.0 / UDP example.com").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.protocol(), "SIP");
        assert_eq!(entry.version(), "2.0");
        assert_eq!(entry.transport(), "UDP");
        assert_eq!(entry.host(), "example.com");
        assert_eq!(entry.port(), None);
    }

    #[test]
    fn sws_around_sent_by_colon() {
        let via = SipVia::parse("SIP/2.0/UDP example.com : 5060;branch=z9hG4bK1").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.host(), "example.com");
        assert_eq!(entry.port(), Some(5060));
        assert_eq!(entry.branch(), Some("z9hG4bK1"));
    }

    #[test]
    fn sws_around_ipv6_reference_colon() {
        let via = SipVia::parse("SIP/2.0/UDP [2001:db8::1] : 5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.host(), "2001:db8::1");
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn empty_transport_before_sent_by_accepted() {
        let via = SipVia::parse("SIP/2.0/ example.com:5060").unwrap();
        let entry = &via.entries()[0];
        assert_eq!(entry.transport(), "");
        assert_eq!(entry.host(), "example.com");
        assert_eq!(entry.port(), Some(5060));
    }

    #[test]
    fn junk_after_sent_by_is_error() {
        assert!(SipVia::parse("SIP/2.0/UDP example.com extra").is_err());
        assert!(SipVia::parse("SIP/2.0/UDP/X example.com").is_err());
        assert!(SipVia::parse("SIP/2.0/UDP").is_err());
    }

    #[test]
    fn unbracketed_ipv6_is_error() {
        assert!(matches!(
            SipVia::parse("SIP/2.0/UDP 2001:db8::1:5060"),
            Err(SipViaError::InvalidFormat(_))
        ));
        assert!(SipVia::parse("SIP/2.0/UDP 2001:db8::1").is_err());
    }

    #[test]
    fn params_keep_trimmed_raw_values() {
        let via = SipVia::parse("SIP/2.0/UDP example.com ; Branch = z9hG4bK1 ; rport ; x=\"a;b\"")
            .unwrap();
        let entry = &via.entries()[0];
        assert_eq!(
            entry.params(),
            &[
                ("branch".to_string(), Some("z9hG4bK1".to_string())),
                ("rport".to_string(), None),
                ("x".to_string(), Some("\"a;b\"".to_string())),
            ]
        );
        assert_eq!(entry.rport(), Some(None));
        assert_eq!(
            via.to_string(),
            "SIP/2.0/UDP example.com;branch=z9hG4bK1;rport;x=\"a;b\""
        );
    }

    #[test]
    fn error_display_omits_input() {
        for raw in [
            "SIP/2.0/UDP secret.example.com extra",
            "SIP/2.0/UDP secret.example.com:99999",
            "SIP/2.0/UDP [2001:db8::1]secret",
            "SIP/2.0/UDP example.com;rport=secret",
            "secret",
        ] {
            let err = SipVia::parse(raw).unwrap_err();
            assert!(!err
                .to_string()
                .contains("secret"));
        }
    }

    #[test]
    fn from_entries_empty_is_empty_error() {
        assert!(matches!(
            SipVia::from_entries(std::iter::empty::<&str>()),
            Err(SipViaError::Empty)
        ));
    }
}
