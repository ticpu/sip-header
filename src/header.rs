//! Standard SIP header names and typed lookup trait (RFC 3261 and extensions).
//!
//! Protocol-agnostic catalog of SIP header names with canonical wire casing,
//! plus a [`SipHeaderLookup`] trait providing typed convenience accessors for
//! any key-value store that can look up headers by name.

use crate::call_info::{SipCallInfo, SipCallInfoError};
use crate::header_addr::{ParseSipHeaderAddrError, SipHeaderAddr};
use crate::history_info::{HistoryInfo, HistoryInfoError};

/// Error returned when parsing an unrecognized SIP header name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSipHeaderError(pub String);

impl std::fmt::Display for ParseSipHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown SIP header: {}", self.0)
    }
}

impl std::error::Error for ParseSipHeaderError {}

define_header_enum! {
    error_type: ParseSipHeaderError,
    /// Standard SIP header names with canonical wire casing.
    ///
    /// Each variant maps to the header's canonical form as defined in the
    /// relevant RFC. `FromStr` is case-insensitive; `Display` always emits
    /// the canonical form.
    pub enum SipHeader {
        /// `Accept` (RFC 3261).
        Accept => "Accept",
        /// `Accept-Contact`.
        AcceptContact => "Accept-Contact",
        /// `Accept-Encoding` (RFC 3261).
        AcceptEncoding => "Accept-Encoding",
        /// `Accept-Language` (RFC 3261).
        AcceptLanguage => "Accept-Language",
        /// `Accept-Resource-Priority`.
        AcceptResourcePriority => "Accept-Resource-Priority",
        /// `Additional-Identity`.
        AdditionalIdentity => "Additional-Identity",
        /// `Alert-Info` (RFC 3261).
        AlertInfo => "Alert-Info",
        /// `AlertMsg-Error`.
        AlertmsgError => "AlertMsg-Error",
        /// `Allow` (RFC 3261).
        Allow => "Allow",
        /// `Allow-Events` (RFC 6665).
        AllowEvents => "Allow-Events",
        /// `Answer-Mode`.
        AnswerMode => "Answer-Mode",
        /// `Attestation-Info`.
        AttestationInfo => "Attestation-Info",
        /// `Authentication-Info`.
        AuthenticationInfo => "Authentication-Info",
        /// `Authorization` (RFC 3261).
        Authorization => "Authorization",
        /// `Call-ID` (RFC 3261).
        CallId => "Call-ID",
        /// `Call-Info` (RFC 3261).
        CallInfo => "Call-Info",
        /// `Cellular-Network-Info`.
        CellularNetworkInfo => "Cellular-Network-Info",
        /// `Contact` (RFC 3261).
        Contact => "Contact",
        /// `Content-Disposition` (RFC 3261).
        ContentDisposition => "Content-Disposition",
        /// `Content-Encoding` (RFC 3261).
        ContentEncoding => "Content-Encoding",
        /// `Content-ID`.
        ContentId => "Content-ID",
        /// `Content-Language` (RFC 3261).
        ContentLanguage => "Content-Language",
        /// `Content-Length` (RFC 3261).
        ContentLength => "Content-Length",
        /// `Content-Type` (RFC 3261).
        ContentType => "Content-Type",
        /// `CSeq` (RFC 3261).
        Cseq => "CSeq",
        /// `Date` (RFC 3261).
        Date => "Date",
        /// `DC-Info`.
        DcInfo => "DC-Info",
        /// `Encryption` (deprecated in RFC 3261).
        Encryption => "Encryption",
        /// `Error-Info` (RFC 3261).
        ErrorInfo => "Error-Info",
        /// `Event` (RFC 6665).
        Event => "Event",
        /// `Expires` (RFC 3261).
        Expires => "Expires",
        /// `Feature-Caps`.
        FeatureCaps => "Feature-Caps",
        /// `Flow-Timer`.
        FlowTimer => "Flow-Timer",
        /// `From` (RFC 3261).
        From => "From",
        /// `Geolocation` (RFC 6442).
        Geolocation => "Geolocation",
        /// `Geolocation-Error` (RFC 6442).
        GeolocationError => "Geolocation-Error",
        /// `Geolocation-Routing` (RFC 6442).
        GeolocationRouting => "Geolocation-Routing",
        /// `Hide` (deprecated in RFC 3261).
        Hide => "Hide",
        /// `History-Info` (RFC 7044).
        HistoryInfo => "History-Info",
        /// `Identity` (RFC 8224).
        Identity => "Identity",
        /// `Identity-Info`.
        IdentityInfo => "Identity-Info",
        /// `Info-Package`.
        InfoPackage => "Info-Package",
        /// `In-Reply-To` (RFC 3261).
        InReplyTo => "In-Reply-To",
        /// `Join` (RFC 3911).
        Join => "Join",
        /// `Max-Breadth`.
        MaxBreadth => "Max-Breadth",
        /// `Max-Forwards` (RFC 3261).
        MaxForwards => "Max-Forwards",
        /// `MIME-Version` (RFC 3261).
        MimeVersion => "MIME-Version",
        /// `Min-Expires` (RFC 3261).
        MinExpires => "Min-Expires",
        /// `Min-SE` (RFC 4028).
        MinSe => "Min-SE",
        /// `Organization` (RFC 3261).
        Organization => "Organization",
        /// `Origination-Id`.
        OriginationId => "Origination-Id",
        /// `P-Access-Network-Info`.
        PAccessNetworkInfo => "P-Access-Network-Info",
        /// `P-Answer-State`.
        PAnswerState => "P-Answer-State",
        /// `P-Asserted-Identity` (RFC 3325).
        PAssertedIdentity => "P-Asserted-Identity",
        /// `P-Asserted-Service`.
        PAssertedService => "P-Asserted-Service",
        /// `P-Associated-URI`.
        PAssociatedUri => "P-Associated-URI",
        /// `P-Called-Party-ID`.
        PCalledPartyId => "P-Called-Party-ID",
        /// `P-Charge-Info`.
        PChargeInfo => "P-Charge-Info",
        /// `P-Charging-Function-Addresses`.
        PChargingFunctionAddresses => "P-Charging-Function-Addresses",
        /// `P-Charging-Vector`.
        PChargingVector => "P-Charging-Vector",
        /// `P-DCS-Trace-Party-ID`.
        PDcsTracePartyId => "P-DCS-Trace-Party-ID",
        /// `P-DCS-OSPS`.
        PDcsOsps => "P-DCS-OSPS",
        /// `P-DCS-Billing-Info`.
        PDcsBillingInfo => "P-DCS-Billing-Info",
        /// `P-DCS-LAES`.
        PDcsLaes => "P-DCS-LAES",
        /// `P-DCS-Redirect`.
        PDcsRedirect => "P-DCS-Redirect",
        /// `P-Early-Media`.
        PEarlyMedia => "P-Early-Media",
        /// `P-Media-Authorization`.
        PMediaAuthorization => "P-Media-Authorization",
        /// `P-Preferred-Identity` (RFC 3325).
        PPreferredIdentity => "P-Preferred-Identity",
        /// `P-Preferred-Service`.
        PPreferredService => "P-Preferred-Service",
        /// `P-Private-Network-Indication`.
        PPrivateNetworkIndication => "P-Private-Network-Indication",
        /// `P-Profile-Key`.
        PProfileKey => "P-Profile-Key",
        /// `P-Refused-URI-List`.
        PRefusedUriList => "P-Refused-URI-List",
        /// `P-Served-User`.
        PServedUser => "P-Served-User",
        /// `P-User-Database`.
        PUserDatabase => "P-User-Database",
        /// `P-Visited-Network-ID`.
        PVisitedNetworkId => "P-Visited-Network-ID",
        /// `Path` (RFC 3327).
        Path => "Path",
        /// `Permission-Missing`.
        PermissionMissing => "Permission-Missing",
        /// `Policy-Contact`.
        PolicyContact => "Policy-Contact",
        /// `Policy-ID`.
        PolicyId => "Policy-ID",
        /// `Priority` (RFC 3261).
        Priority => "Priority",
        /// `Priority-Share`.
        PriorityShare => "Priority-Share",
        /// `Priority-Verstat`.
        PriorityVerstat => "Priority-Verstat",
        /// `Priv-Answer-Mode`.
        PrivAnswerMode => "Priv-Answer-Mode",
        /// `Privacy` (RFC 3323).
        Privacy => "Privacy",
        /// `Proxy-Authenticate` (RFC 3261).
        ProxyAuthenticate => "Proxy-Authenticate",
        /// `Proxy-Authorization` (RFC 3261).
        ProxyAuthorization => "Proxy-Authorization",
        /// `Proxy-Require` (RFC 3261).
        ProxyRequire => "Proxy-Require",
        /// `RAck`.
        Rack => "RAck",
        /// `Reason` (RFC 3326).
        Reason => "Reason",
        /// `Reason-Phrase`.
        ReasonPhrase => "Reason-Phrase",
        /// `Record-Route` (RFC 3261).
        RecordRoute => "Record-Route",
        /// `Recv-Info`.
        RecvInfo => "Recv-Info",
        /// `Refer-Events-At`.
        ReferEventsAt => "Refer-Events-At",
        /// `Refer-Sub`.
        ReferSub => "Refer-Sub",
        /// `Refer-To` (RFC 3515).
        ReferTo => "Refer-To",
        /// `Referred-By` (RFC 3892).
        ReferredBy => "Referred-By",
        /// `Reject-Contact`.
        RejectContact => "Reject-Contact",
        /// `Relayed-Charge`.
        RelayedCharge => "Relayed-Charge",
        /// `Replaces` (RFC 3891).
        Replaces => "Replaces",
        /// `Reply-To` (RFC 3261).
        ReplyTo => "Reply-To",
        /// `Request-Disposition`.
        RequestDisposition => "Request-Disposition",
        /// `Require` (RFC 3261).
        Require => "Require",
        /// `Resource-Priority`.
        ResourcePriority => "Resource-Priority",
        /// `Resource-Share`.
        ResourceShare => "Resource-Share",
        /// `Response-Key` (deprecated in RFC 3261).
        ResponseKey => "Response-Key",
        /// `Response-Source`.
        ResponseSource => "Response-Source",
        /// `Restoration-Info`.
        RestorationInfo => "Restoration-Info",
        /// `Retry-After` (RFC 3261).
        RetryAfter => "Retry-After",
        /// `Route` (RFC 3261).
        Route => "Route",
        /// `RSeq`.
        Rseq => "RSeq",
        /// `Security-Client` (RFC 3329).
        SecurityClient => "Security-Client",
        /// `Security-Server` (RFC 3329).
        SecurityServer => "Security-Server",
        /// `Security-Verify` (RFC 3329).
        SecurityVerify => "Security-Verify",
        /// `Server` (RFC 3261).
        Server => "Server",
        /// `Service-Interact-Info`.
        ServiceInteractInfo => "Service-Interact-Info",
        /// `Service-Route` (RFC 3608).
        ServiceRoute => "Service-Route",
        /// `Session-Expires` (RFC 4028).
        SessionExpires => "Session-Expires",
        /// `Session-ID`.
        SessionId => "Session-ID",
        /// `SIP-ETag`.
        SipEtag => "SIP-ETag",
        /// `SIP-If-Match`.
        SipIfMatch => "SIP-If-Match",
        /// `Subject` (RFC 3261).
        Subject => "Subject",
        /// `Subscription-State` (RFC 6665).
        SubscriptionState => "Subscription-State",
        /// `Supported` (RFC 3261).
        Supported => "Supported",
        /// `Suppress-If-Match`.
        SuppressIfMatch => "Suppress-If-Match",
        /// `Target-Dialog` (RFC 4538).
        TargetDialog => "Target-Dialog",
        /// `Timestamp` (RFC 3261).
        Timestamp => "Timestamp",
        /// `To` (RFC 3261).
        To => "To",
        /// `Trigger-Consent`.
        TriggerConsent => "Trigger-Consent",
        /// `Unsupported` (RFC 3261).
        Unsupported => "Unsupported",
        /// `User-Agent` (RFC 3261).
        UserAgent => "User-Agent",
        /// `User-to-User` (RFC 7433).
        UserToUser => "User-to-User",
        /// `Via` (RFC 3261).
        Via => "Via",
        /// `Warning` (RFC 3261).
        Warning => "Warning",
        /// `WWW-Authenticate` (RFC 3261).
        WwwAuthenticate => "WWW-Authenticate",
    }
}

/// RFC 3261 §7.3.3 compact header form mappings.
///
/// Includes forms from RFC 3261, RFC 3515, RFC 3841, RFC 3892, RFC 4028,
/// RFC 4474, and RFC 6665.
const COMPACT_FORMS: &[(u8, SipHeader)] = &[
    (b'a', SipHeader::AcceptContact),
    (b'b', SipHeader::ReferredBy),
    (b'c', SipHeader::ContentType),
    (b'd', SipHeader::RequestDisposition),
    (b'e', SipHeader::ContentEncoding),
    (b'f', SipHeader::From),
    (b'i', SipHeader::CallId),
    (b'j', SipHeader::RejectContact),
    (b'k', SipHeader::Supported),
    (b'l', SipHeader::ContentLength),
    (b'm', SipHeader::Contact),
    (b'n', SipHeader::IdentityInfo),
    (b'o', SipHeader::Event),
    (b'r', SipHeader::ReferTo),
    (b's', SipHeader::Subject),
    (b't', SipHeader::To),
    (b'u', SipHeader::AllowEvents),
    (b'v', SipHeader::Via),
    (b'x', SipHeader::SessionExpires),
    (b'y', SipHeader::Identity),
];

impl SipHeader {
    /// Resolve a compact form letter to the corresponding header (RFC 3261 §7.3.3).
    ///
    /// Case-insensitive: both `'f'` and `'F'` resolve to [`SipHeader::From`].
    pub fn from_compact(ch: u8) -> Option<Self> {
        let lower = ch.to_ascii_lowercase();
        COMPACT_FORMS
            .iter()
            .find(|(c, _)| *c == lower)
            .map(|(_, h)| *h)
    }

    /// Return the compact form letter for this header, if one exists.
    pub fn compact_form(&self) -> Option<char> {
        COMPACT_FORMS
            .iter()
            .find(|(_, h)| h == self)
            .map(|(c, _)| *c as char)
    }

    /// Parse a header name, including RFC 3261 §7.3.3 compact forms.
    ///
    /// Tries compact form resolution for single-character input, then
    /// falls back to case-insensitive canonical name matching.
    pub fn parse_name(name: &str) -> Result<Self, ParseSipHeaderError> {
        if name.len() == 1 {
            if let Some(h) = Self::from_compact(name.as_bytes()[0]) {
                return Ok(h);
            }
        }
        name.parse()
    }
}

/// Trait for looking up standard SIP headers from any key-value store.
///
/// Implementors provide `sip_header_str()` and get all typed accessors as
/// default implementations.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeaderLookup, SipHeader};
///
/// let mut headers = HashMap::new();
/// headers.insert(
///     "Call-Info".to_string(),
///     "<urn:emergency:uid:callid:abc>;purpose=emergency-CallId".to_string(),
/// );
///
/// assert_eq!(
///     headers.sip_header(SipHeader::CallInfo),
///     Some("<urn:emergency:uid:callid:abc>;purpose=emergency-CallId"),
/// );
///
/// let ci = headers.call_info().unwrap().unwrap();
/// assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
/// ```
pub trait SipHeaderLookup {
    /// Look up a SIP header by its canonical name (e.g. `"Call-Info"`).
    fn sip_header_str(&self, name: &str) -> Option<&str>;

    /// Look up a SIP header by its [`SipHeader`] enum variant.
    fn sip_header(&self, name: SipHeader) -> Option<&str> {
        self.sip_header_str(name.as_str())
    }

    /// Raw `Call-Info` header value (RFC 3261 section 20.9).
    fn call_info_raw(&self) -> Option<&str> {
        self.sip_header(SipHeader::CallInfo)
    }

    /// Parse the `Call-Info` header into a [`SipCallInfo`].
    ///
    /// Returns `Ok(None)` if the header is absent, `Err` if present but unparseable.
    fn call_info(&self) -> Result<Option<SipCallInfo>, SipCallInfoError> {
        match self.call_info_raw() {
            Some(s) => SipCallInfo::parse(s).map(Some),
            None => Ok(None),
        }
    }

    /// Raw `History-Info` header value (RFC 7044).
    fn history_info_raw(&self) -> Option<&str> {
        self.sip_header(SipHeader::HistoryInfo)
    }

    /// Parse the `History-Info` header into a [`HistoryInfo`].
    ///
    /// Returns `Ok(None)` if the header is absent, `Err` if present but unparseable.
    fn history_info(&self) -> Result<Option<HistoryInfo>, HistoryInfoError> {
        match self.history_info_raw() {
            Some(s) => HistoryInfo::parse(s).map(Some),
            None => Ok(None),
        }
    }

    /// Raw `P-Asserted-Identity` header value (RFC 3325).
    fn p_asserted_identity_raw(&self) -> Option<&str> {
        self.sip_header(SipHeader::PAssertedIdentity)
    }

    /// Parse the `P-Asserted-Identity` header into a [`SipHeaderAddr`].
    ///
    /// Returns `Ok(None)` if the header is absent, `Err` if present but unparseable.
    fn p_asserted_identity(&self) -> Result<Option<SipHeaderAddr>, ParseSipHeaderAddrError> {
        match self.p_asserted_identity_raw() {
            Some(s) => s
                .parse::<SipHeaderAddr>()
                .map(Some),
            None => Ok(None),
        }
    }
}

impl SipHeaderLookup for std::collections::HashMap<String, String> {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.get(name)
            .map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn display_round_trip() {
        assert_eq!(SipHeader::CallInfo.to_string(), "Call-Info");
        assert_eq!(SipHeader::HistoryInfo.to_string(), "History-Info");
        assert_eq!(
            SipHeader::PAssertedIdentity.to_string(),
            "P-Asserted-Identity"
        );
    }

    #[test]
    fn as_ref_str() {
        let h: &str = SipHeader::CallInfo.as_ref();
        assert_eq!(h, "Call-Info");
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("call-info".parse::<SipHeader>(), Ok(SipHeader::CallInfo));
        assert_eq!("CALL-INFO".parse::<SipHeader>(), Ok(SipHeader::CallInfo));
        assert_eq!(
            "history-info".parse::<SipHeader>(),
            Ok(SipHeader::HistoryInfo)
        );
        assert_eq!(
            "p-asserted-identity".parse::<SipHeader>(),
            Ok(SipHeader::PAssertedIdentity)
        );
        assert_eq!(
            "P-ASSERTED-IDENTITY".parse::<SipHeader>(),
            Ok(SipHeader::PAssertedIdentity)
        );
    }

    #[test]
    fn from_str_unknown() {
        assert!("X-Custom"
            .parse::<SipHeader>()
            .is_err());
    }

    #[test]
    fn from_str_round_trip_all() {
        let variants = [
            SipHeader::Accept,
            SipHeader::AcceptContact,
            SipHeader::AcceptEncoding,
            SipHeader::AcceptLanguage,
            SipHeader::AcceptResourcePriority,
            SipHeader::AdditionalIdentity,
            SipHeader::AlertInfo,
            SipHeader::AlertmsgError,
            SipHeader::Allow,
            SipHeader::AllowEvents,
            SipHeader::AnswerMode,
            SipHeader::AttestationInfo,
            SipHeader::AuthenticationInfo,
            SipHeader::Authorization,
            SipHeader::CallId,
            SipHeader::CallInfo,
            SipHeader::CellularNetworkInfo,
            SipHeader::Contact,
            SipHeader::ContentDisposition,
            SipHeader::ContentEncoding,
            SipHeader::ContentId,
            SipHeader::ContentLanguage,
            SipHeader::ContentLength,
            SipHeader::ContentType,
            SipHeader::Cseq,
            SipHeader::Date,
            SipHeader::DcInfo,
            SipHeader::Encryption,
            SipHeader::ErrorInfo,
            SipHeader::Event,
            SipHeader::Expires,
            SipHeader::FeatureCaps,
            SipHeader::FlowTimer,
            SipHeader::From,
            SipHeader::Geolocation,
            SipHeader::GeolocationError,
            SipHeader::GeolocationRouting,
            SipHeader::Hide,
            SipHeader::HistoryInfo,
            SipHeader::Identity,
            SipHeader::IdentityInfo,
            SipHeader::InfoPackage,
            SipHeader::InReplyTo,
            SipHeader::Join,
            SipHeader::MaxBreadth,
            SipHeader::MaxForwards,
            SipHeader::MimeVersion,
            SipHeader::MinExpires,
            SipHeader::MinSe,
            SipHeader::Organization,
            SipHeader::OriginationId,
            SipHeader::PAccessNetworkInfo,
            SipHeader::PAnswerState,
            SipHeader::PAssertedIdentity,
            SipHeader::PAssertedService,
            SipHeader::PAssociatedUri,
            SipHeader::PCalledPartyId,
            SipHeader::PChargeInfo,
            SipHeader::PChargingFunctionAddresses,
            SipHeader::PChargingVector,
            SipHeader::PDcsTracePartyId,
            SipHeader::PDcsOsps,
            SipHeader::PDcsBillingInfo,
            SipHeader::PDcsLaes,
            SipHeader::PDcsRedirect,
            SipHeader::PEarlyMedia,
            SipHeader::PMediaAuthorization,
            SipHeader::PPreferredIdentity,
            SipHeader::PPreferredService,
            SipHeader::PPrivateNetworkIndication,
            SipHeader::PProfileKey,
            SipHeader::PRefusedUriList,
            SipHeader::PServedUser,
            SipHeader::PUserDatabase,
            SipHeader::PVisitedNetworkId,
            SipHeader::Path,
            SipHeader::PermissionMissing,
            SipHeader::PolicyContact,
            SipHeader::PolicyId,
            SipHeader::Priority,
            SipHeader::PriorityShare,
            SipHeader::PriorityVerstat,
            SipHeader::PrivAnswerMode,
            SipHeader::Privacy,
            SipHeader::ProxyAuthenticate,
            SipHeader::ProxyAuthorization,
            SipHeader::ProxyRequire,
            SipHeader::Rack,
            SipHeader::Reason,
            SipHeader::ReasonPhrase,
            SipHeader::RecordRoute,
            SipHeader::RecvInfo,
            SipHeader::ReferEventsAt,
            SipHeader::ReferSub,
            SipHeader::ReferTo,
            SipHeader::ReferredBy,
            SipHeader::RejectContact,
            SipHeader::RelayedCharge,
            SipHeader::Replaces,
            SipHeader::ReplyTo,
            SipHeader::RequestDisposition,
            SipHeader::Require,
            SipHeader::ResourcePriority,
            SipHeader::ResourceShare,
            SipHeader::ResponseKey,
            SipHeader::ResponseSource,
            SipHeader::RestorationInfo,
            SipHeader::RetryAfter,
            SipHeader::Route,
            SipHeader::Rseq,
            SipHeader::SecurityClient,
            SipHeader::SecurityServer,
            SipHeader::SecurityVerify,
            SipHeader::Server,
            SipHeader::ServiceInteractInfo,
            SipHeader::ServiceRoute,
            SipHeader::SessionExpires,
            SipHeader::SessionId,
            SipHeader::SipEtag,
            SipHeader::SipIfMatch,
            SipHeader::Subject,
            SipHeader::SubscriptionState,
            SipHeader::Supported,
            SipHeader::SuppressIfMatch,
            SipHeader::TargetDialog,
            SipHeader::Timestamp,
            SipHeader::To,
            SipHeader::TriggerConsent,
            SipHeader::Unsupported,
            SipHeader::UserAgent,
            SipHeader::UserToUser,
            SipHeader::Via,
            SipHeader::Warning,
            SipHeader::WwwAuthenticate,
        ];
        for v in variants {
            let wire = v.to_string();
            let parsed: SipHeader = wire
                .parse()
                .unwrap();
            assert_eq!(parsed, v, "round-trip failed for {wire}");
        }
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sip_header_by_enum() {
        let h = headers_with(&[("Call-Info", "<urn:x>;purpose=icon")]);
        assert_eq!(
            h.sip_header(SipHeader::CallInfo),
            Some("<urn:x>;purpose=icon")
        );
    }

    #[test]
    fn call_info_raw_lookup() {
        let h = headers_with(&[(
            "Call-Info",
            "<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId",
        )]);
        assert_eq!(
            h.call_info_raw(),
            Some("<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId")
        );
    }

    #[test]
    fn call_info_typed() {
        let h = headers_with(&[(
            "Call-Info",
            "<urn:emergency:uid:callid:test:bcf.example.com>;purpose=emergency-CallId",
        )]);
        let ci = h
            .call_info()
            .unwrap()
            .unwrap();
        assert_eq!(ci.len(), 1);
        assert_eq!(ci.entries()[0].purpose(), Some("emergency-CallId"));
    }

    #[test]
    fn call_info_absent() {
        let h = headers_with(&[]);
        assert_eq!(
            h.call_info()
                .unwrap(),
            None
        );
    }

    #[test]
    fn p_asserted_identity_raw_lookup() {
        let h = headers_with(&[(
            "P-Asserted-Identity",
            r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>"#,
        )]);
        assert_eq!(
            h.p_asserted_identity_raw(),
            Some(r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>"#)
        );
    }

    #[test]
    fn p_asserted_identity_typed() {
        let h = headers_with(&[(
            "P-Asserted-Identity",
            r#""EXAMPLE CO" <sip:+15551234567@198.51.100.1>"#,
        )]);
        let pai = h
            .p_asserted_identity()
            .unwrap()
            .unwrap();
        assert_eq!(pai.display_name(), Some("EXAMPLE CO"));
    }

    #[test]
    fn p_asserted_identity_absent() {
        let h = headers_with(&[]);
        assert_eq!(
            h.p_asserted_identity()
                .unwrap(),
            None
        );
    }

    #[test]
    fn history_info_raw_lookup() {
        let h = headers_with(&[(
            "History-Info",
            "<sip:alice@esrp.example.com>;index=1,<sip:sos@psap.example.com>;index=1.1",
        )]);
        assert!(h
            .history_info_raw()
            .unwrap()
            .contains("esrp.example.com"));
    }

    #[test]
    fn history_info_typed() {
        let h = headers_with(&[(
            "History-Info",
            "<sip:alice@esrp.example.com>;index=1,<sip:sos@psap.example.com>;index=1.1",
        )]);
        let hi = h
            .history_info()
            .unwrap()
            .unwrap();
        assert_eq!(hi.len(), 2);
        assert_eq!(hi.entries()[0].index(), Some("1"));
        assert_eq!(hi.entries()[1].index(), Some("1.1"));
    }

    #[test]
    fn history_info_absent() {
        let h = headers_with(&[]);
        assert_eq!(
            h.history_info()
                .unwrap(),
            None
        );
    }

    #[test]
    fn extract_from_sip_message() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "Call-Info: <urn:emergency:uid:callid:abc>;purpose=emergency-CallId\r\n",
            "History-Info: <sip:esrp@example.com>;index=1\r\n",
            "P-Asserted-Identity: \"Corp\" <sip:+15551234567@198.51.100.1>\r\n",
            "\r\n",
        );
        assert_eq!(
            SipHeader::CallInfo.extract_from(msg),
            Some("<urn:emergency:uid:callid:abc>;purpose=emergency-CallId".into())
        );
        assert_eq!(
            SipHeader::HistoryInfo.extract_from(msg),
            Some("<sip:esrp@example.com>;index=1".into())
        );
        assert_eq!(
            SipHeader::PAssertedIdentity.extract_from(msg),
            Some("\"Corp\" <sip:+15551234567@198.51.100.1>".into())
        );
    }

    #[test]
    fn extract_from_missing() {
        let msg = concat!(
            "INVITE sip:bob@host SIP/2.0\r\n",
            "From: Alice <sip:alice@host>\r\n",
            "\r\n",
        );
        assert_eq!(SipHeader::CallInfo.extract_from(msg), None);
        assert_eq!(SipHeader::PAssertedIdentity.extract_from(msg), None);
    }

    #[test]
    fn missing_headers_return_none() {
        let h = headers_with(&[]);
        assert_eq!(h.call_info_raw(), None);
        assert_eq!(
            h.call_info()
                .unwrap(),
            None
        );
        assert_eq!(h.history_info_raw(), None);
        assert_eq!(
            h.history_info()
                .unwrap(),
            None
        );
        assert_eq!(h.p_asserted_identity_raw(), None);
        assert_eq!(
            h.p_asserted_identity()
                .unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod compact_form_tests {
    use super::*;

    #[test]
    fn from_compact_known() {
        assert_eq!(SipHeader::from_compact(b'f'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact(b'F'), Some(SipHeader::From));
        assert_eq!(SipHeader::from_compact(b'v'), Some(SipHeader::Via));
        assert_eq!(SipHeader::from_compact(b'i'), Some(SipHeader::CallId));
        assert_eq!(SipHeader::from_compact(b'm'), Some(SipHeader::Contact));
        assert_eq!(SipHeader::from_compact(b't'), Some(SipHeader::To));
        assert_eq!(SipHeader::from_compact(b'c'), Some(SipHeader::ContentType));
    }

    #[test]
    fn from_compact_unknown() {
        assert_eq!(SipHeader::from_compact(b'z'), None);
        assert_eq!(SipHeader::from_compact(b'g'), None);
    }

    #[test]
    fn compact_form_roundtrip() {
        assert_eq!(SipHeader::From.compact_form(), Some('f'));
        assert_eq!(SipHeader::Via.compact_form(), Some('v'));
        assert_eq!(SipHeader::CallId.compact_form(), Some('i'));
        assert_eq!(SipHeader::Contact.compact_form(), Some('m'));
    }

    #[test]
    fn compact_form_absent() {
        assert_eq!(SipHeader::HistoryInfo.compact_form(), None);
        assert_eq!(SipHeader::PAssertedIdentity.compact_form(), None);
    }

    #[test]
    fn parse_name_compact() {
        assert_eq!(SipHeader::parse_name("f"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("F"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("v"), Ok(SipHeader::Via));
    }

    #[test]
    fn parse_name_full() {
        assert_eq!(SipHeader::parse_name("From"), Ok(SipHeader::From));
        assert_eq!(SipHeader::parse_name("Via"), Ok(SipHeader::Via));
    }

    #[test]
    fn parse_name_unknown() {
        assert!(SipHeader::parse_name("X-Custom").is_err());
    }

    #[test]
    fn all_compact_forms_resolve() {
        let expected = [
            ('a', SipHeader::AcceptContact),
            ('b', SipHeader::ReferredBy),
            ('c', SipHeader::ContentType),
            ('d', SipHeader::RequestDisposition),
            ('e', SipHeader::ContentEncoding),
            ('f', SipHeader::From),
            ('i', SipHeader::CallId),
            ('j', SipHeader::RejectContact),
            ('k', SipHeader::Supported),
            ('l', SipHeader::ContentLength),
            ('m', SipHeader::Contact),
            ('n', SipHeader::IdentityInfo),
            ('o', SipHeader::Event),
            ('r', SipHeader::ReferTo),
            ('s', SipHeader::Subject),
            ('t', SipHeader::To),
            ('u', SipHeader::AllowEvents),
            ('v', SipHeader::Via),
            ('x', SipHeader::SessionExpires),
            ('y', SipHeader::Identity),
        ];
        for (ch, header) in expected {
            assert_eq!(
                SipHeader::from_compact(ch as u8),
                Some(header),
                "compact form '{ch}' failed"
            );
            assert_eq!(
                header.compact_form(),
                Some(ch),
                "compact_form() for {} failed",
                header
            );
        }
    }
}

#[cfg(test)]
mod special_case_tests {
    use super::*;

    #[test]
    fn cseq_variants() {
        assert_eq!("CSeq".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!("cseq".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!("CSEQ".parse::<SipHeader>(), Ok(SipHeader::Cseq));
        assert_eq!(SipHeader::Cseq.to_string(), "CSeq");
    }

    #[test]
    fn www_authenticate_variants() {
        assert_eq!(
            "WWW-Authenticate".parse::<SipHeader>(),
            Ok(SipHeader::WwwAuthenticate)
        );
        assert_eq!(
            "www-authenticate".parse::<SipHeader>(),
            Ok(SipHeader::WwwAuthenticate)
        );
        assert_eq!(SipHeader::WwwAuthenticate.to_string(), "WWW-Authenticate");
    }

    #[test]
    fn rack_rseq_variants() {
        assert_eq!("RAck".parse::<SipHeader>(), Ok(SipHeader::Rack));
        assert_eq!("rack".parse::<SipHeader>(), Ok(SipHeader::Rack));
        assert_eq!(SipHeader::Rack.to_string(), "RAck");

        assert_eq!("RSeq".parse::<SipHeader>(), Ok(SipHeader::Rseq));
        assert_eq!("rseq".parse::<SipHeader>(), Ok(SipHeader::Rseq));
        assert_eq!(SipHeader::Rseq.to_string(), "RSeq");
    }

    #[test]
    fn user_to_user_variants() {
        assert_eq!(
            "User-to-User".parse::<SipHeader>(),
            Ok(SipHeader::UserToUser)
        );
        assert_eq!(
            "user-to-user".parse::<SipHeader>(),
            Ok(SipHeader::UserToUser)
        );
        assert_eq!(SipHeader::UserToUser.to_string(), "User-to-User");
    }

    #[test]
    fn p_header_variants() {
        assert_eq!(
            "P-DCS-Trace-Party-ID".parse::<SipHeader>(),
            Ok(SipHeader::PDcsTracePartyId)
        );
        assert_eq!(
            "p-dcs-trace-party-id".parse::<SipHeader>(),
            Ok(SipHeader::PDcsTracePartyId)
        );
        assert_eq!(
            SipHeader::PDcsTracePartyId.to_string(),
            "P-DCS-Trace-Party-ID"
        );
    }
}
