//! A read-ahead cache for media ranges.
//!
//! A `<video>` element reads its file in many small `Range` requests, and each
//! one costs a round trip to the CDN. When such a request is for a video or
//! audio file, the proxy fetches a larger window around it once, keeps it, and
//! answers the next requests that fall inside that window from memory.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Bytes fetched for one request: enough to cover the reads that follow it.
pub const WINDOW: u64 = 2 * 1024 * 1024;
/// Most bytes kept at once; the oldest windows go first.
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// How long a window is kept. Signed URLs expire, so this also bounds how long
/// their bytes stay in memory.
const TTL: Duration = Duration::from_secs(300);

static CACHE: LazyLock<Mutex<RangeCache>> = LazyLock::new(|| Mutex::new(RangeCache::default()));

/// The process-wide cache of media windows.
pub fn cache() -> MutexGuard<'static, RangeCache> {
    CACHE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The last byte to fetch to answer a request for `start..=end` (or from
/// `start` to the end of the file when `end` is `None`): the whole requested
/// range, and at least a window's worth.
pub fn fetch_end(start: u64, end: Option<u64>) -> u64 {
    end.unwrap_or(0).max(start + WINDOW - 1)
}

/// Whether a response of this content type is cached at all: only media is, so
/// pages and scripts are never held back.
pub fn is_media(content_type: &str) -> bool {
    content_type.starts_with("video/") || content_type.starts_with("audio/")
}

/// The `start` and `end` of a single `bytes=` range. `end` is `None` for an
/// open-ended `bytes=start-`. Suffix ranges (`bytes=-500`) and multi-part
/// ranges are not handled, and yield `None`.
pub fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = match end.trim() {
        "" => None,
        end => {
            let end: u64 = end.parse().ok()?;
            if end < start {
                return None;
            }
            Some(end)
        }
    };
    Some((start, end))
}

/// The `first`, `last` and total length of a `Content-Range` value such as
/// `bytes 0-99/1000`. The total is `None` when the server says `*`.
pub fn parse_content_range(value: &str) -> Option<(u64, u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes ")?;
    let (range, total) = spec.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let first: u64 = first.parse().ok()?;
    let last: u64 = last.parse().ok()?;
    let total = match total {
        "*" => None,
        total => Some(total.parse().ok()?),
    };
    (last >= first).then_some((first, last, total))
}

/// A window of a file: `data` holds the bytes from `start` onwards.
pub struct Window {
    pub start: u64,
    pub data: Vec<u8>,
    pub total: Option<u64>,
    pub content_type: String,
    stored: Instant,
}

impl Window {
    pub fn new(start: u64, data: Vec<u8>, total: Option<u64>, content_type: String) -> Self {
        Self {
            start,
            data,
            total,
            content_type,
            stored: Instant::now(),
        }
    }
}

/// Part of a window, ready to be sent as a `206` response.
pub struct Slice {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// One window per URL. A URL's bytes do not change, so a window only needs to
/// go when it is too old or when room is needed.
#[derive(Default)]
pub struct RangeCache {
    windows: HashMap<String, Window>,
    bytes: usize,
}

impl RangeCache {
    /// The bytes of `start..=end` for `url`, if one window holds all of them.
    /// `end` is clipped to the end of the file when its length is known.
    pub fn get(&mut self, url: &str, start: u64, end: u64) -> Option<Slice> {
        self.expire();
        let window = self.windows.get(url)?;
        let end = match window.total {
            Some(total) => end.min(total.checked_sub(1)?),
            None => end,
        };
        let window_end = window.start + window.data.len() as u64 - 1;
        if start < window.start || start > end || end > window_end {
            return None;
        }
        let from = (start - window.start) as usize;
        let to = (end - window.start) as usize + 1;
        Some(Slice {
            start,
            end,
            total: window.total,
            content_type: window.content_type.clone(),
            data: window.data[from..to].to_vec(),
        })
    }

    /// Keeps `window` for `url`, replacing any earlier one, and makes room for
    /// it by dropping the oldest windows first. A window larger than the whole
    /// cache is not kept.
    pub fn put(&mut self, url: String, window: Window) {
        self.expire();
        if window.data.len() > MAX_BYTES {
            return;
        }
        if let Some(old) = self.windows.remove(&url) {
            self.bytes -= old.data.len();
        }
        while self.bytes + window.data.len() > MAX_BYTES {
            let oldest = self
                .windows
                .iter()
                .min_by_key(|(_, window)| window.stored)
                .map(|(url, _)| url.clone());
            let Some(oldest) = oldest else { break };
            if let Some(old) = self.windows.remove(&oldest) {
                self.bytes -= old.data.len();
            }
        }
        self.bytes += window.data.len();
        self.windows.insert(url, window);
    }

    fn expire(&mut self) {
        let bytes = &mut self.bytes;
        self.windows.retain(|_, window| {
            let fresh = window.stored.elapsed() < TTL;
            if !fresh {
                *bytes -= window.data.len();
            }
            fresh
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ranges() {
        assert_eq!(parse_range("bytes=0-99"), Some((0, Some(99))));
        assert_eq!(parse_range("bytes=1301396-"), Some((1301396, None)));
        assert_eq!(parse_range("bytes=-500"), None);
        assert_eq!(parse_range("bytes=0-1,5-6"), None);
        assert_eq!(parse_range("bytes=9-3"), None);
        assert_eq!(parse_range("items=0-9"), None);
    }

    #[test]
    fn parses_content_range() {
        assert_eq!(parse_content_range("bytes 0-99/1000"), Some((0, 99, Some(1000))));
        assert_eq!(parse_content_range("bytes 0-99/*"), Some((0, 99, None)));
        assert_eq!(parse_content_range("bytes */1000"), None);
        assert_eq!(parse_content_range("bytes 9-3/1000"), None);
    }

    #[test]
    fn answers_ranges_inside_a_window_and_nothing_else() {
        let mut cache = RangeCache::default();
        let data: Vec<u8> = (0..=99).collect();
        cache.put(
            "https://cdn/x".into(),
            Window::new(10, data, Some(1000), "video/mp4".into()),
        );

        let hit = cache.get("https://cdn/x", 20, 29).unwrap();
        assert_eq!((hit.start, hit.end, hit.total), (20, 29, Some(1000)));
        assert_eq!(hit.data, (10..=19).collect::<Vec<u8>>());

        assert!(cache.get("https://cdn/x", 5, 29).is_none(), "starts before the window");
        assert!(cache.get("https://cdn/x", 100, 120).is_none(), "ends after the window");
        assert!(cache.get("https://cdn/other", 20, 29).is_none());
    }

    #[test]
    fn clips_a_range_at_the_end_of_the_file() {
        let mut cache = RangeCache::default();
        cache.put(
            "u".into(),
            Window::new(0, vec![7; 50], Some(50), "audio/mp4".into()),
        );
        let hit = cache.get("u", 40, 999).unwrap();
        assert_eq!((hit.start, hit.end), (40, 49));
        assert_eq!(hit.data.len(), 10);
    }

    #[test]
    fn evicts_the_oldest_window_to_make_room() {
        let mut cache = RangeCache::default();
        let big = MAX_BYTES / 2 + 1;
        cache.put("a".into(), Window::new(0, vec![0; big], None, "video/mp4".into()));
        cache.put("b".into(), Window::new(0, vec![0; big], None, "video/mp4".into()));
        assert!(cache.get("a", 0, 0).is_none(), "the oldest was not evicted");
        assert!(cache.get("b", 0, 0).is_some());
        assert!(cache.bytes <= MAX_BYTES);
    }

    #[test]
    fn only_media_is_cached() {
        assert!(is_media("video/mp4"));
        assert!(is_media("audio/mp4"));
        assert!(!is_media("text/html"));
        assert!(!is_media("application/json"));
    }
}
