# Design Rationale

## Quote-aware comma splitting

SIP headers use commas to delimit list entries (RFC 3261 section 7.3.1), but
commas also appear inside angle-bracketed URIs and inside quoted strings.
The original `split_comma_entries` tracked only angle-bracket depth, which
worked for URI-bearing headers (Contact, Route, Call-Info) but silently
broke any header whose values contain quoted strings with commas.

The Warning header exposed this: `warn-text` is a `quoted-string` that
may legitimately contain commas. Input like
`301 example.com "text, with comma", 399 example.org "fine"` was
incorrectly split into three fragments.

Rather than adding a second, Warning-specific splitter, `split_comma_entries`
was extended to track quote state (with backslash-escape awareness for
`quoted-pair` per section 25.1). This also made the auth-specific
`split_auth_params` redundant — it was a strict subset of the new logic,
just without bracket depth tracking. It was deleted and all auth param
splitting now goes through the shared function.

## Auth param quoting: unescaping and qop

### Quoted-pair round-trip

The auth parser stripped outer quotes from parameter values but did not
process `quoted-pair` escape sequences (`\"`, `\\`) inside them. The
Display implementation *did* escape via `write_quoted`. This meant a
value like `realm="foo\"bar"` was stored with the literal `\"` intact,
then re-serialized as `realm="foo\\\"bar"` — a double-escape that broke
round-trip fidelity.

The fix adds `unescape_quoted_pair` at parse time, mirroring
`write_quoted_pair` at display time. Both are shared helpers in `lib.rs`
since the same RFC 3261 section 25.1 `quoted-pair` semantics apply to
Warning, auth params, and display-name quoted strings.

### qop quoting depends on context

RFC 2617 section 3.2.1 specifies `qop` as a quoted string in challenge
headers (WWW-Authenticate), while section 3.2.2 specifies it as an
unquoted token in credential headers (Authorization). Since
`SipAuthValue` represents both roles, the `qop` key was removed from the
always-quote list. The Display fallback still quotes any value containing
commas, whitespace, or quote characters — so `qop="auth,auth-int"` in
challenges is quoted because of the comma, while `qop=auth` in
Authorization correctly stays unquoted.

## Shared quoted-string helpers

Three modules independently implemented RFC 3261 section 25.1
`quoted-pair` unescaping (auth, warning, header_addr) and two
implemented escaping (auth, warning). The core logic was extracted into
`lib.rs` as `unescape_quoted_pair`, `escape_quoted_pair`, and
`write_quoted_pair`. The `header_addr` parser was not changed — its
`parse_quoted_string` interleaves position tracking with unescaping via
`char_indices` to return both the unescaped content and the remainder of
the input, which is a fundamentally different control flow that does not
benefit from sharing.

## Accept media_range storage

`SipAcceptEntry` originally stored `media_type` and `subtype` as two
separate `String` fields. The `media_range()` accessor called
`format!("{}/{}", ...)` on every invocation, allocating each time.

Since the slash position is known at parse time and the combined string
is the most commonly accessed form (matching, display), the struct now
stores a single `media_range: String` with a `slash_pos: usize` index.
The accessors `media_type()` and `subtype()` slice into it. The slash
position cannot become stale because the fields are private and no
mutators are exposed.

## FromStr via macro

All comma-separated header types follow the same pattern: a
`pub fn parse(&str) -> Result<Self, Error>` constructor with `FromStr`
delegating to it. The `impl_from_str_via_parse!` macro eliminates the
boilerplate, replacing six identical eight-line impl blocks with
one-line invocations.

## Body extraction shares the header boundary

Callers re-deriving the header/body boundary as `split_once("\r\n\r\n")`
silently lose the body on bare-`\n` messages this crate accepts, so
`extract_body` and the header extractors share one boundary helper. The
splitter stays private: a public one would freeze header-block slice
semantics we haven't needed to define, and exposing it later is
non-breaking.

## Replaces framing is an explicit constructor

`SipReplaces` (and `SipTargetDialog`) parse both the wire header value and
the hnv-encoded (hnv = RFC 3261 section 25 `hname`/`hvalue` charset)
URI-header form found inside a Refer-To, where `@`, `;` and `=` remain
percent-encoded after sip-uri's canonicalisation. `%` is a legal
call-id `word` character, so a value cannot reveal which framing it is in —
`parse` and `parse_uri_header` are separate constructors, and Display
re-emits the framing the instance was parsed from. The encoded framing
re-encodes to canonical hnv form (uppercase hex), matching sip-uri's
canonicalised output, so round-trip is against that form rather than the
producer's original hex casing.

## Mutators validate against the grammar their parser does not enforce

A parser's leniency is what makes real traffic survivable; a value handed to a
mutator never crossed the wire, so it earns none of that — an unchecked Call-ID
set on a dialog identifier re-serializes into a header naming a different dialog.
Public mutators therefore return `Result` and check the RFC production for the
field they set, and the resulting asymmetry stands: a value `parse` accepted can
be rejected when set back through a mutator.

## extract_header returns Vec

The 0.2 API joined multiple occurrences of the same header with `, `.
RFC 3261 section 7.3.1 explicitly forbids this for Authorization,
Proxy-Authorization, WWW-Authenticate, and Proxy-Authenticate. Returning
`Vec<String>` preserves per-occurrence boundaries and lets the caller
decide whether joining is appropriate. The `SipHeaderLookup` trait gained
`sip_header_all_str` / `sip_header_all` to expose multi-occurrence
values from any backing store, and every list accessor on the trait reads
through them, splitting each row untrimmed: a present row that is only
whitespace surfaces the entry parser's error rather than `Empty`, because
trimming would turn a blank list header into an empty list instead of an
error.

## Catalog parse errors never carry the rejected bytes in Display

Errors generated by `define_header_enum!` render a label and the byte length
of the rejected input, never the input; the bytes stay on the public field for
a caller that decides to print them. Display reaches every consumer's `{e}`
log line outside whatever redaction the consumer applies, and a rejected header
or variable name is wire content.

## List-valued types take pre-split entries

Every comma-list type has a `from_entries` constructor beside `parse`, each
keeping that type's strictness. A caller holding entries a transport already
delimited never re-joins them for `parse`: the second split is a guess over
boundaries already drawn, and it hides which layer produced a bad entry.
