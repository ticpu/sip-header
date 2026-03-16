#!/bin/bash
# Compare SipHeader enum variants against IANA SIP header registry.
#
# Usage: check-sip-headers.sh
#
# Reads header names from iana-sip-headers.txt and compares with the
# SipHeader enum in src/header.rs.
#
# Output: last line is "SipHeader <rust_count>/<iana_count>"
# Exit: 0 on match, 1 on mismatch

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
IANA_FILE="$REPO_ROOT/iana-sip-headers.txt"
RUST_FILE="$REPO_ROOT/src/header.rs"

if [ ! -f "$IANA_FILE" ]; then
	echo "error: $IANA_FILE not found" >&2
	exit 1
fi

if [ ! -f "$RUST_FILE" ]; then
	echo "error: $RUST_FILE not found" >&2
	exit 1
fi

# Extract IANA header names (one per line, trim whitespace)
iana_names=$(grep -v '^$' "$IANA_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort)

# Extract Rust wire names from the SipHeader enum definition
# Look for lines matching the pattern: VariantName => "Header-Name",
# within the define_header_enum! block for SipHeader
rust_names=$(sed -n '/pub enum SipHeader {/,/^[[:space:]]*}$/p' "$RUST_FILE" \
	| grep -oP '=> "\K[^"]+(?=")' \
	| sort)

rust_count=$(echo "$rust_names" | wc -l)
iana_count=$(echo "$iana_names" | wc -l)

missing_in_rust=$(comm -23 <(echo "$iana_names") <(echo "$rust_names"))
extra_in_rust=$(comm -13 <(echo "$iana_names") <(echo "$rust_names"))

rc=0

if [ -n "$missing_in_rust" ]; then
	echo "SipHeader missing from IANA registry:"
	echo "$missing_in_rust" | sed 's/^/  + /'
	rc=1
fi

if [ -n "$extra_in_rust" ]; then
	echo "SipHeader has headers not in IANA registry:"
	echo "$extra_in_rust" | sed 's/^/  - /'
	rc=1
fi

echo "SipHeader ${rust_count}/${iana_count}"

exit $rc
