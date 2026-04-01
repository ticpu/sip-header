//! SIP authentication value parser (RFC 3261 §20.7, §20.27, §20.28, §20.44).

use std::fmt;
use std::str::FromStr;

/// Error type for SIP authentication value parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipAuthError {
    /// The input string was empty.
    Empty,
    /// The input string had an invalid format.
    InvalidFormat(String),
}

impl fmt::Display for SipAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty authentication value"),
            Self::InvalidFormat(msg) => write!(f, "invalid authentication format: {}", msg),
        }
    }
}

impl std::error::Error for SipAuthError {}

/// Parsed SIP authentication value.
///
/// Covers Authorization, Proxy-Authorization, WWW-Authenticate, and
/// Proxy-Authenticate header field values.
///
/// Grammar: `scheme SP param=val *(COMMA param=val)`
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAuthValue {
    scheme: String,
    params: Vec<(String, String)>,
}

impl SipAuthValue {
    /// Returns the authentication scheme (e.g., "Digest", "Bearer").
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns all authentication parameters as key-value pairs.
    ///
    /// Keys are lowercased. Values have quotes stripped.
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// Returns the value of a named parameter.
    ///
    /// Key lookup is case-insensitive.
    pub fn param(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the `realm` parameter value.
    pub fn realm(&self) -> Option<&str> {
        self.param("realm")
    }

    /// Returns the `nonce` parameter value.
    pub fn nonce(&self) -> Option<&str> {
        self.param("nonce")
    }

    /// Returns the `algorithm` parameter value.
    pub fn algorithm(&self) -> Option<&str> {
        self.param("algorithm")
    }

    /// Returns the `username` parameter value.
    pub fn username(&self) -> Option<&str> {
        self.param("username")
    }

    /// Returns the `opaque` parameter value.
    pub fn opaque(&self) -> Option<&str> {
        self.param("opaque")
    }

    /// Returns the `qop` parameter value.
    pub fn qop(&self) -> Option<&str> {
        self.param("qop")
    }
}

impl FromStr for SipAuthValue {
    type Err = SipAuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SipAuthError::Empty);
        }

        // Find the first whitespace to split scheme from params
        let (scheme, rest) = match s.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((scheme, rest)) => (scheme, rest.trim_start()),
            None => {
                // No params, just a scheme
                return Ok(SipAuthValue {
                    scheme: s.to_string(),
                    params: Vec::new(),
                });
            }
        };

        let mut params = Vec::new();

        // Split on commas (parameter separators)
        for param_str in rest.split(',') {
            let param_str = param_str.trim();
            if param_str.is_empty() {
                continue;
            }

            // Split on '=' to get key and value
            let (key, value) = param_str
                .split_once('=')
                .ok_or_else(|| {
                    SipAuthError::InvalidFormat(format!("missing '=' in parameter: {}", param_str))
                })?;

            let key = key
                .trim()
                .to_ascii_lowercase();
            let mut value = value.trim();

            // Strip quotes if present
            if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                value = &value[1..value.len() - 1];
            }

            params.push((key, value.to_string()));
        }

        Ok(SipAuthValue {
            scheme: scheme.to_string(),
            params,
        })
    }
}

impl fmt::Display for SipAuthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.scheme)?;

        if !self
            .params
            .is_empty()
        {
            write!(f, " ")?;
            for (i, (key, value)) in self
                .params
                .iter()
                .enumerate()
            {
                if i > 0 {
                    write!(f, ", ")?;
                }

                // Quote values that contain special characters or spaces
                if value.contains(|c: char| c.is_ascii_whitespace() || c == ',' || c == '"')
                    || value.is_empty()
                {
                    write!(f, "{}=\"{}\"", key, value)?;
                } else {
                    write!(f, "{}={}", key, value)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_digest_full() {
        let input = r#"Digest username="alice", realm="example.com", nonce="dcd98b", uri="sip:example.com", response="6629f""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.username(), Some("alice"));
        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.nonce(), Some("dcd98b"));
        assert_eq!(auth.param("uri"), Some("sip:example.com"));
        assert_eq!(auth.param("response"), Some("6629f"));
    }

    #[test]
    fn parse_digest_with_algorithm() {
        let input = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5, qop="auth""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.nonce(), Some("abc123"));
        assert_eq!(auth.algorithm(), Some("MD5"));
        assert_eq!(auth.qop(), Some("auth"));
    }

    #[test]
    fn parse_bearer_no_params() {
        let input = "Bearer";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(
            auth.params()
                .len(),
            0
        );
    }

    #[test]
    fn parse_scheme_with_single_param() {
        let input = "Bearer token=abc123";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.scheme(), "Bearer");
        assert_eq!(auth.param("token"), Some("abc123"));
    }

    #[test]
    fn parse_empty_input() {
        let result: Result<SipAuthValue, _> = "".parse();
        assert_eq!(result, Err(SipAuthError::Empty));

        let result: Result<SipAuthValue, _> = "   ".parse();
        assert_eq!(result, Err(SipAuthError::Empty));
    }

    #[test]
    fn parse_invalid_param() {
        let input = "Digest username=alice, invalid";
        let result: Result<SipAuthValue, _> = input.parse();
        assert!(matches!(result, Err(SipAuthError::InvalidFormat(_))));
    }

    #[test]
    fn display_roundtrip_quoted() {
        let input = r#"Digest username="alice", realm="example.com", nonce="dcd98b""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();

        // Parse it again to verify it's valid
        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn display_roundtrip_mixed() {
        let input = r#"Digest realm="example.com", algorithm=MD5, qop="auth""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        let output = auth.to_string();

        let auth2: SipAuthValue = output
            .parse()
            .unwrap();
        assert_eq!(auth, auth2);
    }

    #[test]
    fn param_lookup_case_insensitive() {
        let input = r#"Digest Realm="example.com", NONCE="abc123""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.param("realm"), Some("example.com"));
        assert_eq!(auth.param("REALM"), Some("example.com"));
        assert_eq!(auth.param("Realm"), Some("example.com"));
        assert_eq!(auth.param("nonce"), Some("abc123"));
        assert_eq!(auth.param("NONCE"), Some("abc123"));
    }

    #[test]
    fn params_preserves_order() {
        let input = r#"Digest username="alice", realm="example.com", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(
            auth.params()
                .len(),
            3
        );
        assert_eq!(auth.params()[0].0, "username");
        assert_eq!(auth.params()[1].0, "realm");
        assert_eq!(auth.params()[2].0, "nonce");
    }

    #[test]
    fn empty_param_value() {
        let input = r#"Digest username="", realm="example.com""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.username(), Some(""));
        assert_eq!(auth.realm(), Some("example.com"));
    }

    #[test]
    fn unquoted_param() {
        let input = "Digest algorithm=MD5";
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.algorithm(), Some("MD5"));
    }

    #[test]
    fn parse_digest_uri_with_comma() {
        let input = r#"Digest uri="sip:example.com,transport=tcp", realm="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.param("uri"), Some("sip:example.com,transport=tcp"));
        assert_eq!(auth.realm(), Some("test"));
    }

    #[test]
    fn parse_quoted_value_with_multiple_commas() {
        let input = r#"Digest realm="a,b,c", nonce="test""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();
        assert_eq!(auth.realm(), Some("a,b,c"));
        assert_eq!(auth.nonce(), Some("test"));
    }

    #[test]
    fn opaque_param() {
        let input = r#"Digest realm="example.com", opaque="5ccc09c""#;
        let auth: SipAuthValue = input
            .parse()
            .unwrap();

        assert_eq!(auth.realm(), Some("example.com"));
        assert_eq!(auth.opaque(), Some("5ccc09c"));
    }
}
