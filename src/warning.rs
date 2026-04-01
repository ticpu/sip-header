//! SIP Warning header parser (RFC 3261 §20.43).

use std::fmt;
use std::str::FromStr;

/// Error parsing a SIP Warning header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipWarningError {
    /// Empty input.
    Empty,
    /// Invalid format.
    InvalidFormat(String),
}

impl fmt::Display for SipWarningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipWarningError::Empty => write!(f, "empty Warning header"),
            SipWarningError::InvalidFormat(msg) => write!(f, "invalid Warning format: {}", msg),
        }
    }
}

impl std::error::Error for SipWarningError {}

/// A single Warning header entry.
///
/// RFC 3261 §20.43:
/// ```text
/// warning-value = warn-code SP warn-agent SP warn-text
/// warn-code = 3DIGIT
/// warn-agent = hostport / pseudonym
/// warn-text = quoted-string
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipWarningEntry {
    code: u16,
    agent: String,
    text: String,
}

impl SipWarningEntry {
    /// The 3-digit warning code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The warn-agent (hostport or pseudonym).
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// The warn-text (unquoted).
    pub fn text(&self) -> &str {
        &self.text
    }

    fn parse(s: &str) -> Result<Self, SipWarningError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SipWarningError::InvalidFormat(
                "empty warning entry".to_string(),
            ));
        }

        // Parse warn-code (3DIGIT)
        let space_pos = s
            .find(' ')
            .ok_or_else(|| {
                SipWarningError::InvalidFormat("missing space after warn-code".to_string())
            })?;

        let code_str = &s[..space_pos];
        if code_str.len() != 3
            || !code_str
                .chars()
                .all(|c| c.is_ascii_digit())
        {
            return Err(SipWarningError::InvalidFormat(format!(
                "warn-code must be 3 digits, got '{}'",
                code_str
            )));
        }

        let code = code_str
            .parse::<u16>()
            .map_err(|_| {
                SipWarningError::InvalidFormat(format!("invalid warn-code '{}'", code_str))
            })?;

        let rest = s[space_pos..].trim_start();

        // Find the quoted warn-text
        let quote_pos = rest
            .find('"')
            .ok_or_else(|| {
                SipWarningError::InvalidFormat("missing quoted warn-text".to_string())
            })?;

        if quote_pos == 0 {
            return Err(SipWarningError::InvalidFormat(
                "missing warn-agent".to_string(),
            ));
        }

        let agent = rest[..quote_pos]
            .trim_end()
            .to_string();
        if agent.is_empty() {
            return Err(SipWarningError::InvalidFormat(
                "empty warn-agent".to_string(),
            ));
        }

        // Parse quoted string
        let text = parse_quoted_string(&rest[quote_pos..])?;

        Ok(SipWarningEntry { code, agent, text })
    }
}

impl fmt::Display for SipWarningEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:03} {} \"{}\"",
            self.code,
            self.agent,
            escape_quoted_string(&self.text)
        )
    }
}

/// Parse a quoted string starting with '"'.
fn parse_quoted_string(s: &str) -> Result<String, SipWarningError> {
    let s = s.trim_start();
    if !s.starts_with('"') {
        return Err(SipWarningError::InvalidFormat(
            "quoted string must start with '\"'".to_string(),
        ));
    }

    let mut result = String::new();
    let chars = s[1..].chars();
    let mut escaped = false;

    for c in chars {
        if escaped {
            result.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Ok(result);
        } else {
            result.push(c);
        }
    }

    Err(SipWarningError::InvalidFormat(
        "unterminated quoted string".to_string(),
    ))
}

/// Escape a string for use in a quoted-string.
fn escape_quoted_string(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            _ => vec![c],
        })
        .collect()
}

/// SIP Warning header.
///
/// RFC 3261 §20.43:
/// ```text
/// Warning = "Warning" HCOLON warning-value *(COMMA warning-value)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipWarning {
    entries: Vec<SipWarningEntry>,
}

impl SipWarning {
    /// Parse a Warning header value.
    pub fn parse(raw: &str) -> Result<Self, SipWarningError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SipWarningError::Empty);
        }

        let entries = crate::split_comma_entries(raw)
            .into_iter()
            .map(SipWarningEntry::parse)
            .collect::<Result<Vec<_>, _>>()?;

        if entries.is_empty() {
            return Err(SipWarningError::Empty);
        }

        Ok(SipWarning { entries })
    }

    /// All warning entries.
    pub fn entries(&self) -> &[SipWarningEntry] {
        &self.entries
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipWarningEntry> {
        self.entries
    }

    /// Number of warning entries.
    pub fn len(&self) -> usize {
        self.entries
            .len()
    }

    /// Whether there are no warning entries.
    pub fn is_empty(&self) -> bool {
        self.entries
            .is_empty()
    }
}

impl fmt::Display for SipWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.entries, ", ")
    }
}

impl FromStr for SipWarning {
    type Err = SipWarningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl IntoIterator for SipWarning {
    type Item = SipWarningEntry;
    type IntoIter = std::vec::IntoIter<SipWarningEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .into_iter()
    }
}

impl<'a> IntoIterator for &'a SipWarning {
    type Item = &'a SipWarningEntry;
    type IntoIter = std::slice::Iter<'a, SipWarningEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_warning() {
        let input = r#"301 example.com "Incompatible network protocol""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 1);
        let entry = &warning.entries()[0];
        assert_eq!(entry.code(), 301);
        assert_eq!(entry.agent(), "example.com");
        assert_eq!(entry.text(), "Incompatible network protocol");
    }

    #[test]
    fn test_multiple_warnings() {
        let input = r#"301 example.com "Incompatible network protocol", 399 198.51.100.1:5060 "Miscellaneous warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 2);

        let entry1 = &warning.entries()[0];
        assert_eq!(entry1.code(), 301);
        assert_eq!(entry1.agent(), "example.com");
        assert_eq!(entry1.text(), "Incompatible network protocol");

        let entry2 = &warning.entries()[1];
        assert_eq!(entry2.code(), 399);
        assert_eq!(entry2.agent(), "198.51.100.1:5060");
        assert_eq!(entry2.text(), "Miscellaneous warning");
    }

    #[test]
    fn test_escaped_quotes_in_text() {
        let input = r#"399 example.org "Warning with \"quoted\" text""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 1);
        let entry = &warning.entries()[0];
        assert_eq!(entry.code(), 399);
        assert_eq!(entry.agent(), "example.org");
        assert_eq!(entry.text(), r#"Warning with "quoted" text"#);
    }

    #[test]
    fn test_common_warning_codes() {
        let input1 = r#"301 example.com "Incompatible network protocol""#;
        let warning1 = SipWarning::parse(input1).unwrap();
        assert_eq!(warning1.entries()[0].code(), 301);

        let input2 = r#"399 example.net "Miscellaneous warning""#;
        let warning2 = SipWarning::parse(input2).unwrap();
        assert_eq!(warning2.entries()[0].code(), 399);
    }

    #[test]
    fn test_display_roundtrip() {
        let input = r#"301 example.com "Incompatible network protocol", 399 198.51.100.1:5060 "Miscellaneous warning""#;
        let warning = SipWarning::parse(input).unwrap();
        let output = warning.to_string();
        let reparsed = SipWarning::parse(&output).unwrap();
        assert_eq!(warning, reparsed);
    }

    #[test]
    fn test_display_roundtrip_with_escaped_quotes() {
        let input = r#"399 example.org "Warning with \"quoted\" text""#;
        let warning = SipWarning::parse(input).unwrap();
        let output = warning.to_string();
        let reparsed = SipWarning::parse(&output).unwrap();
        assert_eq!(warning, reparsed);
    }

    #[test]
    fn test_empty_input() {
        let result = SipWarning::parse("");
        assert!(matches!(result, Err(SipWarningError::Empty)));

        let result = SipWarning::parse("   ");
        assert!(matches!(result, Err(SipWarningError::Empty)));
    }

    #[test]
    fn test_invalid_warn_code() {
        let result = SipWarning::parse(r#"30 example.com "Short code""#);
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));

        let result = SipWarning::parse(r#"3001 example.com "Long code""#);
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));

        let result = SipWarning::parse(r#"abc example.com "Non-numeric""#);
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));
    }

    #[test]
    fn test_missing_warn_agent() {
        let result = SipWarning::parse(r#"301 "Missing agent""#);
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));
    }

    #[test]
    fn test_missing_warn_text() {
        let result = SipWarning::parse("301 example.com");
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));
    }

    #[test]
    fn test_unterminated_quoted_string() {
        let result = SipWarning::parse(r#"301 example.com "Unterminated"#);
        assert!(matches!(result, Err(SipWarningError::InvalidFormat(_))));
    }

    #[test]
    fn test_into_iterator() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();

        let codes: Vec<u16> = warning
            .into_iter()
            .map(|e| e.code())
            .collect();
        assert_eq!(codes, vec![301, 399]);
    }

    #[test]
    fn test_into_iterator_ref() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();

        let codes: Vec<u16> = (&warning)
            .into_iter()
            .map(|e| e.code())
            .collect();
        assert_eq!(codes, vec![301, 399]);

        assert_eq!(warning.len(), 2);
    }

    #[test]
    fn test_is_empty() {
        let input = r#"301 example.com "Warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert!(!warning.is_empty());
    }

    #[test]
    fn test_into_entries() {
        let input = r#"301 example.com "First", 399 example.org "Second""#;
        let warning = SipWarning::parse(input).unwrap();
        let entries = warning.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].code(), 301);
        assert_eq!(entries[1].code(), 399);
    }

    #[test]
    fn test_comma_in_warn_text() {
        let input = r#"301 example.com "text, with comma", 399 example.org "fine""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.len(), 2);
        assert_eq!(warning.entries()[0].text(), "text, with comma");
        assert_eq!(warning.entries()[1].text(), "fine");
    }

    #[test]
    fn test_from_str() {
        let input = r#"301 example.com "warning""#;
        let warning: SipWarning = input
            .parse()
            .unwrap();
        assert_eq!(warning.len(), 1);
    }

    #[test]
    fn test_ipv6_agent() {
        let input = r#"301 [2001:db8::1]:5060 "IPv6 warning""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.entries()[0].agent(), "[2001:db8::1]:5060");
    }

    #[test]
    fn test_escaped_backslash() {
        let input = r#"399 example.com "Path: C:\\temp\\file""#;
        let warning = SipWarning::parse(input).unwrap();
        assert_eq!(warning.entries()[0].text(), r#"Path: C:\temp\file"#);
    }
}
