//! SIP Accept-Encoding header parser (RFC 3261 §20.2).

use std::fmt;

/// A single Accept-Encoding entry: `encoding *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncodingEntry {
    encoding: String,
    params: Vec<(String, String)>,
}

impl SipAcceptEncodingEntry {
    /// The content-coding value (e.g. `"gzip"`, `"identity"`, `"*"`).
    pub fn encoding(&self) -> &str {
        &self.encoding
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

impl fmt::Display for SipAcceptEncodingEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoding)?;
        for (key, value) in &self.params {
            write!(f, ";{key}={value}")?;
        }
        Ok(())
    }
}

/// Errors from parsing an Accept-Encoding header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipAcceptEncodingError {
    /// The input string was empty or whitespace-only.
    Empty,
    /// An entry could not be parsed.
    InvalidFormat(String),
}

impl fmt::Display for SipAcceptEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty Accept-Encoding header value"),
            Self::InvalidFormat(raw) => write!(f, "invalid Accept-Encoding entry: {raw}"),
        }
    }
}

impl std::error::Error for SipAcceptEncodingError {}

fn parse_entry(raw: &str) -> Result<SipAcceptEncodingEntry, SipAcceptEncodingError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SipAcceptEncodingError::InvalidFormat(raw.to_string()));
    }

    let (encoding_part, params_part) = match raw.split_once(';') {
        Some((e, p)) => (e.trim(), Some(p)),
        None => (raw, None),
    };

    if encoding_part.is_empty() {
        return Err(SipAcceptEncodingError::InvalidFormat(raw.to_string()));
    }

    let encoding = encoding_part.to_ascii_lowercase();
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

    Ok(SipAcceptEncodingEntry { encoding, params })
}

/// Parsed SIP Accept-Encoding header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncoding(Vec<SipAcceptEncodingEntry>);

impl SipAcceptEncoding {
    /// Parse a comma-separated Accept-Encoding header value.
    pub fn parse(raw: &str) -> Result<Self, SipAcceptEncodingError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SipAcceptEncodingError::Empty);
        }
        let entries: Vec<_> = crate::split_comma_entries(raw)
            .into_iter()
            .map(parse_entry)
            .collect::<Result<_, _>>()?;
        if entries.is_empty() {
            return Err(SipAcceptEncodingError::Empty);
        }
        Ok(Self(entries))
    }

    /// The parsed entries as a slice.
    pub fn entries(&self) -> &[SipAcceptEncodingEntry] {
        &self.0
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipAcceptEncodingEntry> {
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

impl fmt::Display for SipAcceptEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.0, ", ")
    }
}

impl<'a> IntoIterator for &'a SipAcceptEncoding {
    type Item = &'a SipAcceptEncodingEntry;
    type IntoIter = std::slice::Iter<'a, SipAcceptEncodingEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
    }
}

impl IntoIterator for SipAcceptEncoding {
    type Item = SipAcceptEncodingEntry;
    type IntoIter = std::vec::IntoIter<SipAcceptEncodingEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_encoding() {
        let ae = SipAcceptEncoding::parse("gzip").unwrap();
        assert_eq!(ae.len(), 1);
        assert_eq!(ae.entries()[0].encoding(), "gzip");
    }

    #[test]
    fn multiple_encodings_with_q() {
        let ae = SipAcceptEncoding::parse("gzip;q=1.0, identity;q=0.5").unwrap();
        assert_eq!(ae.len(), 2);
        assert_eq!(ae.entries()[0].q(), Some("1.0"));
        assert_eq!(ae.entries()[1].encoding(), "identity");
    }

    #[test]
    fn wildcard() {
        let ae = SipAcceptEncoding::parse("*").unwrap();
        assert_eq!(ae.entries()[0].encoding(), "*");
    }

    #[test]
    fn empty_input() {
        assert!(matches!(
            SipAcceptEncoding::parse(""),
            Err(SipAcceptEncodingError::Empty)
        ));
    }

    #[test]
    fn display_roundtrip() {
        let raw = "gzip;q=0.8";
        let ae = SipAcceptEncoding::parse(raw).unwrap();
        assert_eq!(ae.to_string(), raw);
    }
}
