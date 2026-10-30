//! What a Worker/SharedWorker gets injected before its own script -- the
//! worker-side mechanics behind `Config::worker_inject_scripts`. The actual
//! scripts are the caller's own business (e.g. t-app builds a
//! `https://` -> scheme rewrite for a worker's own scope with Rsbuild, the
//! same way it builds `inject.ts` for `window`, and lists it in
//! `worker_inject_scripts`); this module only matches, fills in, and
//! prepends them.
//!
//! `inject.ts`'s wrapped `Worker`/`SharedWorker` constructors mark the
//! script's URL with [`MARKER`] before requesting it, both from a page and,
//! from an already-shimmed worker spawning one of its own (whatever script
//! did that shimming is none of this module's business either). The caller
//! reads that back with [`wants`], fetches the real script with
//! [`strip_marker`] applied (the marker is only this proxy's business, not a
//! query parameter the real site should see), and sends back [`prepend`]'s
//! result (built from [`scripts`]) instead of the plain response.

use super::Config;
use super::inject_rules;

/// The marker a worker script's URL carries when it should get the scripts
/// listed in `Config::worker_inject_scripts`.
pub(super) const MARKER: &str = "__rs_worker=1";

/// Whether `query` (a URI's query string, without the leading `?`) carries
/// [`MARKER`].
pub(super) fn wants(query: Option<&str>) -> bool {
    query.is_some_and(|query| query.split('&').any(|pair| pair == MARKER))
}

/// `url` with [`MARKER`] removed from its query string.
pub(super) fn strip_marker(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let kept: Vec<&str> = query.split('&').filter(|pair| *pair != MARKER).collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    }
}

/// Every `Config::worker_inject_scripts` rule that matches this worker
/// (`host`/`path`, its own address being `scheme`/`worker_location`), in the
/// order listed (see [`inject_rules::matching`]), with `__RS_SCHEME__` and
/// `__RS_WORKER_LOCATION__` filled in wherever a script mentions them --
/// placeholders for a worker's own scheme and real address, which a caller's
/// script may need (every worker it runs in is loaded from a `blob:` URL, so
/// it can't read either off `self.location` itself); a no-op on any script
/// that doesn't. `worker_location` lands inside a single-quoted JS string
/// literal, so it is escaped accordingly.
pub(super) fn scripts(config: &Config, scheme: &str, worker_location: &str, host: &str, path: &str) -> Vec<String> {
    let escaped_location = worker_location.replace('\\', "\\\\").replace('\'', "\\'");
    inject_rules::matching(config.worker_inject_scripts, host, path)
        .map(|script| script.replace("__RS_SCHEME__", scheme).replace("__RS_WORKER_LOCATION__", &escaped_location))
        .collect()
}

/// `body`, with `scripts` (see [`scripts`]) run before it, each on its own
/// line. `scripts` empty leaves `body` untouched.
pub(super) fn prepend(body: Vec<u8>, scripts: &[String]) -> Vec<u8> {
    if scripts.is_empty() {
        return body;
    }
    let joined = scripts.join("\n");
    let mut out = Vec::with_capacity(joined.len() + 1 + body.len());
    out.extend_from_slice(joined.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::InjectRule;

    const CONFIG: Config = Config {
        scheme: "htl",
        inject_scripts: &[],
        worker_inject_scripts: &[],
        pns_rules_url: None,
        dev_watched_paths: &[],
        hash_replacements: &[],
    };

    #[test]
    fn detects_the_marker_among_other_params() {
        assert!(wants(Some("a=1&__rs_worker=1&b=2")));
        assert!(wants(Some("__rs_worker=1")));
        assert!(!wants(Some("a=1")));
        assert!(!wants(None));
    }

    #[test]
    fn strips_only_the_marker() {
        assert_eq!(strip_marker("https://h/p?a=1&__rs_worker=1&b=2"), "https://h/p?a=1&b=2");
        assert_eq!(strip_marker("https://h/p?__rs_worker=1"), "https://h/p");
        assert_eq!(strip_marker("https://h/p?a=1"), "https://h/p?a=1");
        assert_eq!(strip_marker("https://h/p"), "https://h/p");
    }

    #[test]
    fn nothing_runs_unless_listed_in_worker_inject_scripts() {
        let got = scripts(&CONFIG, "htl", "htl://h/worker.js", "tiktok.com", "/worker.js");
        assert!(got.is_empty());
    }

    #[test]
    fn only_rules_matching_this_worker_are_included() {
        let config = Config {
            worker_inject_scripts: &[InjectRule { host: "mapgenie.io", path_prefix: "", script: "mine();" }],
            ..CONFIG
        };
        let got = scripts(&config, "htl", "htl://h/worker.js", "tiktok.com", "/worker.js");
        assert!(got.is_empty());
    }

    #[test]
    fn a_matching_script_runs() {
        let config = Config {
            worker_inject_scripts: &[InjectRule { host: "", path_prefix: "", script: "mine();" }],
            ..CONFIG
        };
        let got = scripts(&config, "htl", "htl://h/worker.js", "tiktok.com", "/worker.js");
        assert_eq!(got, vec!["mine();".to_string()]);
    }

    #[test]
    fn fills_in_the_scheme_and_worker_location_placeholders_of_a_matching_script() {
        let config = Config {
            worker_inject_scripts: &[InjectRule {
                host: "",
                path_prefix: "",
                script: "scheme=__RS_SCHEME__ loc='__RS_WORKER_LOCATION__'",
            }],
            ..CONFIG
        };
        let got = scripts(&config, "htl", r"htl://h/it's\here.js", "tiktok.com", "/worker.js");
        assert_eq!(got[0], r"scheme=htl loc='htl://h/it\'s\\here.js'");
    }

    #[test]
    fn prepends_every_script_before_the_body_on_its_own_line() {
        let out = prepend(b"real();".to_vec(), &["first();".to_string(), "second();".to_string()]);
        assert_eq!(out, b"first();\nsecond();\nreal();");
    }

    #[test]
    fn an_empty_script_list_leaves_the_body_untouched() {
        assert_eq!(prepend(b"real();".to_vec(), &[]), b"real();");
    }
}
