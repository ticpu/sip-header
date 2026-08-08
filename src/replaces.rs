//! RFC 3891 `Replaces` header parser.
//!
//! Also serves `Join` (RFC 3911), whose grammar is identical:
//! `callid *(SEMI param)` with mandatory `to-tag` and `from-tag`.

use std::fmt;

use percent_encoding::percent_decode_str;

/// Error parsing a Replaces header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipReplacesError {
    /// The Replaces header value is empty.
    Empty,
    /// The Replaces header value has an invalid format.
    InvalidFormat(String),
}

impl fmt::Display for SipReplacesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Replaces header is empty"),
            Self::InvalidFormat(msg) => write!(f, "Invalid Replaces format: {}", msg),
        }
    }
}

impl std::error::Error for SipReplacesError {}

impl From<DialogIdError> for SipReplacesError {
    fn from(e: DialogIdError) -> Self {
        match e {
            DialogIdError::Empty => Self::Empty,
            DialogIdError::Invalid(msg) => Self::InvalidFormat(msg),
        }
    }
}

pub(crate) enum DialogIdError {
    Empty,
    Invalid(String),
}

pub(crate) struct DialogId {
    pub call_id: String,
    pub first_tag: String,
    pub second_tag: String,
    pub early_only: bool,
    pub params: Vec<(String, Option<String>)>,
}

/// Parse `callid *(SEMI param)` with two mandatory tag params.
///
/// `early-only` is recognized as a flag only when `with_early_only` is set
/// (RFC 3891 defines it; RFC 4538 does not).
pub(crate) fn parse_dialog_id(
    raw: &str,
    first_tag_name: &str,
    second_tag_name: &str,
    with_early_only: bool,
) -> Result<DialogId, DialogIdError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DialogIdError::Empty);
    }

    let mut segments = trimmed.split(';');
    let call_id = segments
        .next()
        .unwrap_or("")
        .trim();
    if call_id.is_empty() {
        return Err(DialogIdError::Invalid("missing call-id".to_string()));
    }

    let mut first_tag: Option<String> = None;
    let mut second_tag: Option<String> = None;
    let mut early_only = false;
    let mut params = Vec::new();

    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if let Some((key, value)) = segment.split_once('=') {
            let key = key
                .trim()
                .to_ascii_lowercase();
            let value = value.trim();
            let slot = if key == first_tag_name {
                Some(&mut first_tag)
            } else if key == second_tag_name {
                Some(&mut second_tag)
            } else {
                None
            };
            match slot {
                Some(slot) => {
                    if value.is_empty() {
                        return Err(DialogIdError::Invalid(format!("empty {}", key)));
                    }
                    if slot
                        .replace(value.to_string())
                        .is_some()
                    {
                        return Err(DialogIdError::Invalid(format!("duplicate {}", key)));
                    }
                }
                None => params.push((key, Some(value.to_string()))),
            }
        } else {
            let key = segment.to_ascii_lowercase();
            if with_early_only && key == "early-only" {
                early_only = true;
            } else {
                params.push((key, None));
            }
        }
    }

    let first_tag =
        first_tag.ok_or_else(|| DialogIdError::Invalid(format!("missing {}", first_tag_name)))?;
    let second_tag =
        second_tag.ok_or_else(|| DialogIdError::Invalid(format!("missing {}", second_tag_name)))?;

    Ok(DialogId {
        call_id: call_id.to_string(),
        first_tag,
        second_tag,
        early_only,
        params,
    })
}

/// Decode a percent-encoded URI-header value for dialog-id parsing.
pub(crate) fn decode_uri_header_value(raw: &str) -> Result<String, DialogIdError> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| DialogIdError::Invalid(format!("percent-decoded value is not UTF-8: {}", e)))
}

/// A parsed `Replaces` header value (RFC 3891 §6.1).
///
/// Identifies the dialog to be replaced: Call-ID plus the mandatory
/// `to-tag` and `from-tag`. Also used for `Join` (RFC 3911 §7.1), whose
/// grammar is identical.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipReplaces {
    call_id: String,
    to_tag: String,
    from_tag: String,
    early_only: bool,
    params: Vec<(String, Option<String>)>,
    uri_header_framing: bool,
}

impl SipReplaces {
    /// Parse a wire-form header value: `callid;to-tag=x;from-tag=y`.
    pub fn parse(raw: &str) -> Result<Self, SipReplacesError> {
        let id = parse_dialog_id(raw, "to-tag", "from-tag", true)?;
        Ok(Self {
            call_id: id.call_id,
            to_tag: id.first_tag,
            from_tag: id.second_tag,
            early_only: id.early_only,
            params: id.params,
            uri_header_framing: false,
        })
    }

    /// Parse the percent-encoded framing found in a URI header
    /// (`<sip:…?Replaces=…>`), e.g. `callid%40host%3Bto-tag%3Dx%3Bfrom-tag%3Dy`.
    ///
    /// Accepts the canonicalised value returned by
    /// [`sip_uri::SipUri::header`]; [`Display`](fmt::Display) re-encodes to
    /// that same canonical form (uppercase hex).
    pub fn parse_uri_header(raw: &str) -> Result<Self, SipReplacesError> {
        let decoded = decode_uri_header_value(raw)?;
        let mut parsed = Self::parse(&decoded)?;
        parsed.uri_header_framing = true;
        Ok(parsed)
    }

    /// The Call-ID of the dialog being replaced.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The host part of the Call-ID (after `@`), if present.
    pub fn host(&self) -> Option<&str> {
        self.call_id
            .split_once('@')
            .map(|(_, host)| host)
    }

    /// The mandatory `to-tag` value.
    pub fn to_tag(&self) -> &str {
        &self.to_tag
    }

    /// The mandatory `from-tag` value.
    pub fn from_tag(&self) -> &str {
        &self.from_tag
    }

    /// Whether the `early-only` flag is present (RFC 3891 §3).
    pub fn early_only(&self) -> bool {
        self.early_only
    }

    /// Returns all generic parameters (tags and `early-only` excluded).
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Returns a specific generic parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
            .map(|(_, v)| v.as_deref())
    }

    fn wire_form(&self) -> String {
        let mut s = format!(
            "{};to-tag={};from-tag={}",
            self.call_id, self.to_tag, self.from_tag
        );
        if self.early_only {
            s.push_str(";early-only");
        }
        write_params(&mut s, &self.params);
        s
    }
}

pub(crate) fn write_params(s: &mut String, params: &[(String, Option<String>)]) {
    for (key, value) in params {
        s.push(';');
        s.push_str(key);
        if let Some(value) = value {
            s.push('=');
            s.push_str(value);
        }
    }
}

impl fmt::Display for SipReplaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire_form();
        if self.uri_header_framing {
            f.write_str(&sip_uri::encode_uri_header(&wire))
        } else {
            f.write_str(&wire)
        }
    }
}

impl_from_str_via_parse!(SipReplaces, SipReplacesError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let r = SipReplaces::parse("abc123@203.0.113.5;to-tag=t1;from-tag=f1").unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
        assert!(!r.early_only());
    }

    #[test]
    fn host_none_without_at() {
        let r = SipReplaces::parse("abc123;to-tag=t1;from-tag=f1").unwrap();
        assert_eq!(r.call_id(), "abc123");
        assert_eq!(r.host(), None);
    }

    #[test]
    fn early_only_flag() {
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1;early-only").unwrap();
        assert!(r.early_only());
    }

    #[test]
    fn param_names_case_insensitive_values_preserved() {
        let r = SipReplaces::parse("abc@example.com;TO-TAG=T1abc;From-Tag=F1xyz").unwrap();
        assert_eq!(r.to_tag(), "T1abc");
        assert_eq!(r.from_tag(), "F1xyz");
    }

    #[test]
    fn generic_params_preserved() {
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1;foo=bar;flag").unwrap();
        assert_eq!(r.param("foo"), Some(Some("bar")));
        assert_eq!(r.param("flag"), Some(None));
        assert_eq!(r.param("missing"), None);
        assert_eq!(
            r.params()
                .len(),
            2
        );
    }

    #[test]
    fn missing_to_tag_fails() {
        assert!(SipReplaces::parse("abc@example.com;from-tag=f1").is_err());
    }

    #[test]
    fn missing_from_tag_fails() {
        assert!(SipReplaces::parse("abc@example.com;to-tag=t1").is_err());
    }

    #[test]
    fn duplicate_to_tag_fails() {
        assert!(SipReplaces::parse("abc@example.com;to-tag=t1;to-tag=t2;from-tag=f1").is_err());
    }

    #[test]
    fn empty_fails() {
        assert!(matches!(
            SipReplaces::parse(""),
            Err(SipReplacesError::Empty)
        ));
        assert!(matches!(
            SipReplaces::parse("  "),
            Err(SipReplacesError::Empty)
        ));
    }

    #[test]
    fn parse_uri_header_encoded() {
        let r = SipReplaces::parse_uri_header("abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1")
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
    }

    #[test]
    fn parse_uri_header_lowercase_hex() {
        let r = SipReplaces::parse_uri_header("abc123%40203.0.113.5%3bto-tag%3dt1%3bfrom-tag%3df1")
            .unwrap();
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
    }

    #[test]
    fn parse_uri_header_early_only() {
        let r = SipReplaces::parse_uri_header(
            "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1%3Bearly-only",
        )
        .unwrap();
        assert!(r.early_only());
    }

    #[test]
    fn parse_uri_header_invalid_utf8_fails() {
        assert!(SipReplaces::parse_uri_header("abc%C0%80;to-tag=t1;from-tag=f1").is_err());
    }

    #[test]
    fn display_roundtrip_wire() {
        let input = "abc123@203.0.113.5;to-tag=t1;from-tag=f1;early-only;foo=bar";
        let r = SipReplaces::parse(input).unwrap();
        assert_eq!(r.to_string(), input);
        assert_eq!(SipReplaces::parse(&r.to_string()).unwrap(), r);
    }

    #[test]
    fn display_roundtrip_uri_header() {
        let input = "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1";
        let r = SipReplaces::parse_uri_header(input).unwrap();
        assert_eq!(r.to_string(), input);
        assert_eq!(SipReplaces::parse_uri_header(&r.to_string()).unwrap(), r);
    }

    #[test]
    fn from_str_is_wire_framing() {
        let r: SipReplaces = "abc123@203.0.113.5;to-tag=t1;from-tag=f1"
            .parse()
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
    }
}
