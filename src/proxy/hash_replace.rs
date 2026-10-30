//! Swaps a fetched resource's body for another's, when it is a known one
//! fetched from a known URL: some sites occasionally serve a broken body at
//! a URL that normally works, and a fixed replacement is wanted only for
//! that exact (known-broken) body, not for whatever else the URL might
//! later serve (unlike [`super::pns_rules`], which replaces by URL alone,
//! before the fetch, regardless of content).

use sha2::{Digest, Sha256};

/// What to serve instead of a matched body.
pub enum Replace {
    /// Fetch this URL and use its entire response (status, headers and
    /// body) in place of the original.
    Url(&'static str),
    /// Use this content as the body, keeping the original response's
    /// status and headers. For a fixed asset known at build time, e.g.
    /// `Bytes(include_bytes!("fixed.png"))`, the same way `tiktok.rs`
    /// embeds `inject.js`.
    Bytes(&'static [u8]),
}

/// A known resource body, identified by the URL it was fetched from and its
/// SHA-256 hash (lowercase hex, as [`hash_of`] renders it), and what to
/// serve instead of it.
pub struct Replacement {
    /// The URL to match against the one fetched (query string included only
    /// when [`match_query`](Self::match_query) is set).
    pub url: &'static str,
    /// Whether `url` must match the fetched URL's query string too. A query
    /// string is often cache-busting or session-specific and not reliably
    /// reproducible, so most entries want `false` (matched on scheme, host
    /// and path alone); set `true` only when the query string itself is
    /// part of what identifies this resource.
    pub match_query: bool,
    pub hash: &'static str,
    pub replace_with: Replace,
}

/// `body`'s SHA-256 hash, as lowercase hex.
fn hash_of(body: &[u8]) -> String {
    Sha256::digest(body).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `url` with its query string, if any, removed.
fn without_query(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

/// What to serve for `body` fetched from `url`, if both match one of
/// `replacements` (each according to its own
/// [`match_query`](Replacement::match_query)).
pub fn find<'a>(replacements: &'a [Replacement], url: &str, body: &[u8]) -> Option<&'a Replace> {
    let bare_url = without_query(url);
    let mut candidates = replacements
        .iter()
        .filter(|r| if r.match_query { r.url == url } else { r.url == bare_url })
        .peekable();
    // Skip hashing when no replacement cares about this URL at all.
    candidates.peek()?;
    let hash = hash_of(body);
    candidates.find(|r| r.hash == hash).map(|r| &r.replace_with)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacement(url: &'static str, match_query: bool, body: &[u8], replace_with: Replace) -> Replacement {
        let hash = hash_of(body);
        Replacement { url, match_query, hash: Box::leak(hash.into_boxed_str()), replace_with }
    }

    fn url_of(replace: &Replace) -> &'static str {
        match replace {
            Replace::Url(url) => url,
            Replace::Bytes(_) => panic!("expected a Url replacement"),
        }
    }

    #[test]
    fn finds_the_replacement_for_a_matching_url_and_hash() {
        let replacements =
            [replacement("https://example.test/broken", false, b"old content", Replace::Url("https://example.test/fixed"))];
        let found = find(&replacements, "https://example.test/broken", b"old content").unwrap();
        assert_eq!(url_of(found), "https://example.test/fixed");
    }

    #[test]
    fn a_matching_hash_at_a_different_url_does_not_match() {
        let replacements =
            [replacement("https://example.test/broken", false, b"old content", Replace::Url("https://example.test/fixed"))];
        assert!(find(&replacements, "https://example.test/other", b"old content").is_none());
    }

    #[test]
    fn a_matching_url_with_a_different_body_does_not_match() {
        let replacements =
            [replacement("https://example.test/broken", false, b"old content", Replace::Url("https://example.test/fixed"))];
        assert!(find(&replacements, "https://example.test/broken", b"other content").is_none());
    }

    #[test]
    fn ignores_the_query_string_unless_match_query_is_set() {
        let replacements =
            [replacement("https://example.test/broken", false, b"old content", Replace::Url("https://example.test/fixed"))];
        let found = find(&replacements, "https://example.test/broken?v=123", b"old content").unwrap();
        assert_eq!(url_of(found), "https://example.test/fixed");
    }

    #[test]
    fn requires_the_exact_query_string_when_match_query_is_set() {
        let replacements = [replacement(
            "https://example.test/broken?v=123",
            true,
            b"old content",
            Replace::Url("https://example.test/fixed"),
        )];
        assert!(find(&replacements, "https://example.test/broken?v=123", b"old content").is_some());
        assert!(find(&replacements, "https://example.test/broken?v=456", b"old content").is_none());
        assert!(find(&replacements, "https://example.test/broken", b"old content").is_none());
    }

    #[test]
    fn can_match_a_static_byte_replacement() {
        let replacements = [replacement("https://example.test/broken", false, b"old content", Replace::Bytes(b"fixed bytes"))];
        let found = find(&replacements, "https://example.test/broken", b"old content").unwrap();
        assert!(matches!(found, Replace::Bytes(b"fixed bytes")));
    }

    #[test]
    fn an_empty_list_matches_nothing() {
        assert!(find(&[], "https://example.test/broken", b"anything").is_none());
    }
}
