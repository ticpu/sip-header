//! RFC 3891 `Replaces` header parser.
//!
//! Also serves `Join` (RFC 3911), whose grammar is identical:
//! `callid *(SEMI param)` with mandatory `to-tag` and `from-tag`.

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
