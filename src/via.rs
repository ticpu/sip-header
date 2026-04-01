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

        // Parse sent-protocol and sent-by
        let parts: Vec<&str> = main_part
            .split_whitespace()
            .collect();
        if parts.len() != 2 {
            return Err(SipViaError::InvalidFormat(format!(
                "expected 'protocol/version/transport host[:port]', got '{}'",
                main_part
            )));
        }

        let sent_protocol = parts[0];
        let sent_by = parts[1];

        // Parse sent-protocol: protocol-name/version/transport
        let protocol_parts: Vec<&str> = sent_protocol
            .split('/')
            .collect();
        if protocol_parts.len() != 3 {
            return Err(SipViaError::InvalidFormat(format!(
                "expected 'protocol/version/transport', got '{}'",
                sent_protocol
            )));
        }

        let protocol_name = protocol_parts[0].to_string();
        let protocol_version = protocol_parts[1].to_string();
        let transport = protocol_parts[2].to_string();

        // Parse sent-by: host[:port]
        // Handle IPv6 bracket notation [::1]:port
        let (host, port) = parse_host_port(sent_by)?;

        // Parse params
        let mut params = Vec::new();
        if let Some(params_str) = params_part {
            for param in params_str.split(';') {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }

                if let Some(eq_idx) = param.find('=') {
                    let key = param[..eq_idx]
                        .trim()
                        .to_ascii_lowercase();
                    let value = param[eq_idx + 1..]
                        .trim()
                        .to_string();
                    params.push((key, Some(value)));
                } else {
                    // Parameter without value (e.g., rport)
                    params.push((param.to_ascii_lowercase(), None));
                }
            }
        }

        let rport = params
            .iter()
            .find(|(k, _)| k == "rport")
            .map(|(_, v)| match v {
                None => Ok(None),
                Some(s) => s
                    .parse::<u16>()
                    .map(Some)
                    .map_err(|_| SipViaError::InvalidFormat(format!("invalid rport value: {s}"))),
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
            if let Some(val) = value {
                write!(f, ";{}={}", key, val)?;
            } else {
                write!(f, ";{}", key)?;
            }
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

        let parts = crate::split_comma_entries(raw);
        let mut entries = Vec::new();

        for part in parts {
            entries.push(SipViaEntry::parse(part)?);
        }

        if entries.is_empty() {
            return Err(SipViaError::Empty);
        }

        Ok(Self { entries })
    }

    /// Returns the Via entries.
    pub fn entries(&self) -> &[SipViaEntry] {
        &self.entries
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
        for (i, entry) in self
            .entries
            .iter()
            .enumerate()
        {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

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

fn parse_host_port(sent_by: &str) -> Result<(String, Option<u16>), SipViaError> {
    // Handle IPv6 bracket notation [::1]:port
    if sent_by.starts_with('[') {
        // Find the closing bracket
        if let Some(close_bracket) = sent_by.find(']') {
            let host = sent_by[1..close_bracket].to_string();
            let remainder = &sent_by[close_bracket + 1..];

            if remainder.is_empty() {
                return Ok((host, None));
            }

            if let Some(port_str) = remainder.strip_prefix(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| {
                        SipViaError::InvalidFormat(format!("invalid port: {}", port_str))
                    })?;
                return Ok((host, Some(port)));
            }

            return Err(SipViaError::InvalidFormat(format!(
                "unexpected characters after IPv6 address: {}",
                remainder
            )));
        } else {
            return Err(SipViaError::InvalidFormat(
                "unclosed IPv6 bracket".to_string(),
            ));
        }
    }

    // IPv4 or hostname with optional port
    // Find the last colon (to handle IPv6 without brackets, though that's not valid in Via)
    if let Some(colon_idx) = sent_by.rfind(':') {
        let host = sent_by[..colon_idx].to_string();
        let port_str = &sent_by[colon_idx + 1..];

        // Check if this looks like an IPv6 address without brackets (invalid but handle gracefully)
        if host.contains(':') {
            // This is likely a bare IPv6 address, return as-is without port
            return Ok((sent_by.to_string(), None));
        }

        let port = port_str
            .parse::<u16>()
            .map_err(|_| SipViaError::InvalidFormat(format!("invalid port: {}", port_str)))?;
        Ok((host, Some(port)))
    } else {
        Ok((sent_by.to_string(), None))
    }
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
}
