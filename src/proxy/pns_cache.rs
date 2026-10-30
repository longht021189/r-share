//! The GET cache of the PNS runtime service worker: a `GET` whose URL carries
//! `__PNS_SW_CACHE__=1` is answered from the cache when it can, and otherwise
//! fetched and kept under its `__PNS_SW_CACHE_KEY__`. A new response for a key
//! replaces the old one, as the worker's cache does.
//!
//! Only successful (`2xx`, not `206`) responses are kept. Unlike the worker's
//! Cache Storage, this cache lives in memory: it starts empty at each launch.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};

use url::Url;

/// One kept response, as the proxy sends it (without CORS headers, which are
/// added for each request).
#[derive(Clone)]
pub struct Cached {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

static CACHE: LazyLock<Mutex<HashMap<String, Cached>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The cache key of `url`, if the worker would cache it.
pub fn key_of(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut marked = false;
    let mut key = None;
    for (name, value) in parsed.query_pairs() {
        match name.as_ref() {
            "__PNS_SW_CACHE__" => marked = value == "1",
            "__PNS_SW_CACHE_KEY__" => key = Some(value.into_owned()),
            _ => {}
        }
    }
    marked.then_some(key).flatten()
}

/// The kept response for `key`, if it is for exactly `url`.
pub fn get(key: &str, url: &str) -> Option<Cached> {
    let cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache.get(key).filter(|cached| cached.url == url).cloned()
}

/// Keeps `response` for `key`, replacing whatever was kept for it.
pub fn put(key: String, response: Cached) {
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache.insert(key, response);
}

/// Whether a response with this status is kept, as in the worker.
pub fn is_cacheable(status: u16) -> bool {
    (200..300).contains(&status) && status != 206
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_marker_and_the_key() {
        assert_eq!(
            key_of("https://a.com/x.js?__PNS_SW_CACHE__=1&__PNS_SW_CACHE_KEY__=to-json-schema"),
            Some("to-json-schema".into())
        );
        assert_eq!(key_of("https://a.com/x.js?__PNS_SW_CACHE__=0&__PNS_SW_CACHE_KEY__=k"), None);
        assert_eq!(key_of("https://a.com/x.js?__PNS_SW_CACHE__=1"), None);
        assert_eq!(key_of("https://a.com/x.js"), None);
    }

    #[test]
    fn keeps_one_response_per_key_and_serves_only_its_url() {
        let first = Cached {
            url: "https://a.com/x.js?__PNS_SW_CACHE__=1&__PNS_SW_CACHE_KEY__=test-key-1".into(),
            status: 200,
            headers: vec![],
            body: b"one".to_vec(),
        };
        let url = first.url.clone();
        put("test-key-1".into(), first);
        assert_eq!(get("test-key-1", &url).unwrap().body, b"one");
        assert!(get("test-key-1", "https://a.com/other").is_none());

        let second = Cached { body: b"two".to_vec(), ..get("test-key-1", &url).unwrap() };
        put("test-key-1".into(), second);
        assert_eq!(get("test-key-1", &url).unwrap().body, b"two");
    }

    #[test]
    fn only_plain_successes_are_kept() {
        assert!(is_cacheable(200));
        assert!(is_cacheable(204));
        assert!(!is_cacheable(206));
        assert!(!is_cacheable(404));
    }
}
