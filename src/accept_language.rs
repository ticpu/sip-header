//! SIP Accept-Language header parser (RFC 3261 §20.3).

use std::fmt;
use std::str::FromStr;

/// A single Accept-Language entry: `language-range *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptLanguageEntry {
    language: String,
    params: Vec<(String, String)>,
}

impl SipAcceptLanguageEntry {
    /// The language tag (e.g. `"en"`, `"en-US"`, `"*"`).
    pub fn language(&self) -> &str {
        &self.language
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

impl fmt::Display for SipAcceptLanguageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.language)?;
        for (key, value) in &self.params {
            write!(f, ";{key}={value}")?;
        }
        Ok(())
    }
}

/// Errors from parsing an Accept-Language header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipAcceptLanguageError {
    /// The input string was empty or whitespace-only.
    Empty,
    /// An entry could not be parsed.
    InvalidFormat(String),
}

impl fmt::Display for SipAcceptLanguageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty Accept-Language header value"),
            Self::InvalidFormat(raw) => write!(f, "invalid Accept-Language entry: {raw}"),
        }
    }
}

impl std::error::Error for SipAcceptLanguageError {}

fn parse_entry(raw: &str) -> Result<SipAcceptLanguageEntry, SipAcceptLanguageError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SipAcceptLanguageError::InvalidFormat(raw.to_string()));
    }

    let (lang_part, params_part) = match raw.split_once(';') {
        Some((l, p)) => (l.trim(), Some(p)),
        None => (raw, None),
    };

    if lang_part.is_empty() {
        return Err(SipAcceptLanguageError::InvalidFormat(raw.to_string()));
    }

    let language = lang_part.to_ascii_lowercase();
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

    Ok(SipAcceptLanguageEntry { language, params })
}

/// Parsed SIP Accept-Language header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptLanguage(Vec<SipAcceptLanguageEntry>);

impl SipAcceptLanguage {
    /// Parse a comma-separated Accept-Language header value.
    pub fn parse(raw: &str) -> Result<Self, SipAcceptLanguageError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SipAcceptLanguageError::Empty);
        }
        let entries: Vec<_> = crate::split_comma_entries(raw)
            .into_iter()
            .map(parse_entry)
            .collect::<Result<_, _>>()?;
        if entries.is_empty() {
            return Err(SipAcceptLanguageError::Empty);
        }
        Ok(Self(entries))
    }

    /// The parsed entries as a slice.
    pub fn entries(&self) -> &[SipAcceptLanguageEntry] {
        &self.0
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipAcceptLanguageEntry> {
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

impl fmt::Display for SipAcceptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.0, ", ")
    }
}

impl FromStr for SipAcceptLanguage {
    type Err = SipAcceptLanguageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl<'a> IntoIterator for &'a SipAcceptLanguage {
    type Item = &'a SipAcceptLanguageEntry;
    type IntoIter = std::slice::Iter<'a, SipAcceptLanguageEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
    }
}

impl IntoIterator for SipAcceptLanguage {
    type Item = SipAcceptLanguageEntry;
    type IntoIter = std::vec::IntoIter<SipAcceptLanguageEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_language() {
        let al = SipAcceptLanguage::parse("en").unwrap();
        assert_eq!(al.len(), 1);
        assert_eq!(al.entries()[0].language(), "en");
    }

    #[test]
    fn multiple_languages_with_q() {
        let al = SipAcceptLanguage::parse("en;q=0.9, fr;q=0.8, *;q=0.1").unwrap();
        assert_eq!(al.len(), 3);
        assert_eq!(al.entries()[0].language(), "en");
        assert_eq!(al.entries()[1].q(), Some("0.8"));
        assert_eq!(al.entries()[2].language(), "*");
    }

    #[test]
    fn language_subtag() {
        let al = SipAcceptLanguage::parse("en-US").unwrap();
        assert_eq!(al.entries()[0].language(), "en-us");
    }

    #[test]
    fn empty_input() {
        assert!(matches!(
            SipAcceptLanguage::parse(""),
            Err(SipAcceptLanguageError::Empty)
        ));
    }

    #[test]
    fn from_str() {
        let al: SipAcceptLanguage = "en"
            .parse()
            .unwrap();
        assert_eq!(al.len(), 1);
    }

    #[test]
    fn display_roundtrip() {
        let raw = "en;q=0.9";
        let al = SipAcceptLanguage::parse(raw).unwrap();
        assert_eq!(al.to_string(), raw);
    }
}
