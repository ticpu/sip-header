//! SIP Accept header parser (RFC 3261 §20.1).

use std::fmt;

/// A single Accept entry: `type/subtype *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEntry {
    media_type: String,
    subtype: String,
    params: Vec<(String, String)>,
}

impl SipAcceptEntry {
    /// The media type (e.g. `"application"`).
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// The media subtype (e.g. `"sdp"`).
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// The full media range as `type/subtype`.
    pub fn media_range(&self) -> String {
        format!("{}/{}", self.media_type, self.subtype)
    }

    /// All parameters as `(key, value)` pairs.
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// Look up a parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// The `q` quality value, if present.
    pub fn q(&self) -> Option<&str> {
        self.param("q")
    }
}

impl fmt::Display for SipAcceptEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.media_type, self.subtype)?;
        for (key, value) in &self.params {
            write!(f, ";{key}={value}")?;
        }
        Ok(())
    }
}

/// Errors from parsing an Accept header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipAcceptError {
    /// The input string was empty or whitespace-only.
    Empty,
    /// An entry could not be parsed.
    InvalidFormat(String),
}

impl fmt::Display for SipAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty Accept header value"),
            Self::InvalidFormat(raw) => write!(f, "invalid Accept entry: {raw}"),
        }
    }
}

impl std::error::Error for SipAcceptError {}

fn parse_accept_entry(raw: &str) -> Result<SipAcceptEntry, SipAcceptError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SipAcceptError::InvalidFormat(raw.to_string()));
    }

    let (media_part, params_part) = match raw.split_once(';') {
        Some((m, p)) => (m.trim(), Some(p)),
        None => (raw, None),
    };

    let (media_type, subtype) = media_part
        .split_once('/')
        .ok_or_else(|| SipAcceptError::InvalidFormat(raw.to_string()))?;

    let media_type = media_type
        .trim()
        .to_ascii_lowercase();
    let subtype = subtype
        .trim()
        .to_ascii_lowercase();

    if media_type.is_empty() || subtype.is_empty() {
        return Err(SipAcceptError::InvalidFormat(raw.to_string()));
    }

    let mut params = Vec::new();
    if let Some(params_str) = params_part {
        for segment in params_str.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if let Some((key, value)) = segment.split_once('=') {
                params.push((
                    key.trim()
                        .to_ascii_lowercase(),
                    value
                        .trim()
                        .to_string(),
                ));
            } else {
                params.push((segment.to_ascii_lowercase(), String::new()));
            }
        }
    }

    Ok(SipAcceptEntry {
        media_type,
        subtype,
        params,
    })
}

/// Parsed SIP Accept header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAccept(Vec<SipAcceptEntry>);

impl SipAccept {
    /// Parse a comma-separated Accept header value.
    pub fn parse(raw: &str) -> Result<Self, SipAcceptError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SipAcceptError::Empty);
        }
        let entries: Vec<_> = crate::split_comma_entries(raw)
            .into_iter()
            .map(parse_accept_entry)
            .collect::<Result<_, _>>()?;
        if entries.is_empty() {
            return Err(SipAcceptError::Empty);
        }
        Ok(Self(entries))
    }

    /// The parsed entries as a slice.
    pub fn entries(&self) -> &[SipAcceptEntry] {
        &self.0
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipAcceptEntry> {
        self.0
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0
            .len()
    }

    /// Returns `true` if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.0
            .is_empty()
    }
}

impl fmt::Display for SipAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.0, ", ")
    }
}

impl<'a> IntoIterator for &'a SipAccept {
    type Item = &'a SipAcceptEntry;
    type IntoIter = std::slice::Iter<'a, SipAcceptEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
    }
}

impl IntoIterator for SipAccept {
    type Item = SipAcceptEntry;
    type IntoIter = std::vec::IntoIter<SipAcceptEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_media_type() {
        let accept = SipAccept::parse("application/sdp").unwrap();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "sdp");
    }

    #[test]
    fn multiple_types() {
        let accept = SipAccept::parse("application/sdp, application/pidf+xml;q=0.5").unwrap();
        assert_eq!(accept.len(), 2);
        assert_eq!(accept.entries()[0].media_range(), "application/sdp");
        assert_eq!(accept.entries()[1].q(), Some("0.5"));
    }

    #[test]
    fn wildcard_type() {
        let accept = SipAccept::parse("*/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "*");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn wildcard_subtype() {
        let accept = SipAccept::parse("application/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn empty_input() {
        assert!(matches!(SipAccept::parse(""), Err(SipAcceptError::Empty)));
    }

    #[test]
    fn missing_slash() {
        assert!(matches!(
            SipAccept::parse("application"),
            Err(SipAcceptError::InvalidFormat(_))
        ));
    }

    #[test]
    fn display_roundtrip() {
        let raw = "application/sdp;q=0.8";
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.to_string(), raw);
    }
}
