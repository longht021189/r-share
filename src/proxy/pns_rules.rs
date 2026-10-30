//! The request rules of TikTok's PNS runtime service worker
//! (`pns-runtime-sw.js`), applied by the proxy: a service worker cannot run on
//! the proxy's scheme, so the rules run here instead.
//!
//! - `replace`: a URL that starts with a key is rewritten to that key's value
//!   before it is fetched (a host swap, e.g. a CDN that is gone);
//! - `blocklist` / `allowlist`: a request outside the lists, or inside the
//!   blocklist, is refused with `410`.
//!
//! The rules are a JSON array on TikTok's CDN, fetched at first use and again
//! every ten minutes. Until a fetch succeeds, the worker's built-in default rule
//! applies, as it does in the worker. A rule is chosen by the page that makes
//! the request (its `Referer`), not by the request itself; a request without a
//! `Referer` is not processed at all, as in the worker.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use url::Url;

use crate::http_client::{HttpClient, Request};

/// How long fetched rules are kept before they are fetched again.
const REFRESH: Duration = Duration::from_secs(600);
/// How long to wait before trying again after a failed fetch.
const RETRY: Duration = Duration::from_secs(60);

/// Substrings of a page URL that exempt its requests: the worker's test and
/// heatmap switches.
const EXEMPT_QUERIES: [&str; 2] = ["is_test_only=1", "slardar_heatmap"];

/// Hosts whose requests are never processed (local development).
const EXEMPT_HOSTS: [&str; 2] = ["127.0.0.1", "localhost"];

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub url_pattern: Vec<String>,
    #[serde(default)]
    pub replace: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub enable_same_origin_block: bool,
    #[serde(default)]
    pub add_replace_header: bool,
}

/// The worker's built-in rule, used until the first successful fetch.
fn default_rule() -> Rule {
    Rule {
        rule_name: "default_rule".into(),
        url_pattern: vec!["*".into()],
        replace: [
            ("http:", "https:"),
            ("https://unpkg.byted-static.com/", "https://sf-unpkg.tiktokcdn.com/obj/unpkg-va/"),
            ("https://s1-imfile.feishucdn.com/", "https://staff-profile.tiktokcdn.com/"),
            ("https://s16-imfile-sg.feishucdn.com/", "https://staff-profile.tiktokcdn.com/"),
            ("https://s3-imfile.feishucdn.com/", "https://staff-profile.tiktokcdn.com/"),
            ("https://pan16.larksuitecdn.com/", "https://staff-profile.tiktokcdn.com/"),
            ("https://sf16-short-sg.bytegoofy.com/", "https://sf-static.tiktokcdn.com/obj/goofy-sg/"),
            ("https://mon.zijieapi.com", "https://mon.tiktokv.com"),
            ("https://verify.snssdk.com", "https://verification-va.byteoversea.com"),
            ("https://vcs.snssdk.com", "https://vcs-va.byteoversea.com"),
        ]
        .into_iter()
        .map(|(from, to)| (from.to_owned(), to.to_owned()))
        .collect(),
        allowlist: Vec::new(),
        blocklist: Vec::new(),
        enable_same_origin_block: false,
        add_replace_header: false,
    }
}

struct State {
    rules: Vec<Rule>,
    /// Whether a fetch has ever succeeded; until then the default rule applies.
    fetched: bool,
    next_refresh: Instant,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Fetches the rules from `url` if they are due. Failures keep the rules
/// already held, and are retried after a minute.
pub async fn refresh(http: &HttpClient, url: &str) {
    let now = Instant::now();
    {
        let mut guard = STATE.lock().unwrap_or_else(|err| err.into_inner());
        let state = guard.get_or_insert_with(|| State {
            rules: vec![default_rule()],
            fetched: false,
            next_refresh: now,
        });
        if now < state.next_refresh {
            return;
        }
        // Claim this refresh, so concurrent requests do not fetch as well.
        state.next_refresh = now + RETRY;
    }

    let fetched = match http.send(Request::get(url)).await {
        Ok(response) if response.status == 200 => {
            serde_json::from_slice::<Vec<Rule>>(&response.body).map_err(|err| err.to_string())
        }
        Ok(response) => Err(format!("status {}", response.status)),
        Err(err) => Err(err.to_string()),
    };

    let mut guard = STATE.lock().unwrap_or_else(|err| err.into_inner());
    let state = guard.get_or_insert_with(|| State {
        rules: vec![default_rule()],
        fetched: false,
        next_refresh: now,
    });
    if let Ok(rules) = fetched {
        state.rules = rules;
        state.fetched = true;
        state.next_refresh = Instant::now() + REFRESH;
    }
}

/// What to do with one request, once the rules have been applied.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Fetch the request as it is.
    Pass,
    /// Fetch `url` instead. `header` says whether to mark the response.
    Replace { url: String, rule: String, header: bool },
    /// Refuse the request with `410`.
    Block { rule: String },
}

/// Applies the current rules to a request for `url` made by the page at `page`.
pub fn apply(page: &Url, url: &str) -> Outcome {
    let guard = STATE.lock().unwrap_or_else(|err| err.into_inner());
    let rules = match guard.as_ref() {
        Some(state) if state.fetched => state.rules.clone(),
        _ => vec![default_rule()],
    };
    apply_rules(&rules, page, url)
}

/// [`apply`], given the rules.
pub fn apply_rules(rules: &[Rule], page: &Url, url: &str) -> Outcome {
    if page.query().is_some_and(|query| EXEMPT_QUERIES.iter().any(|q| query.contains(q))) {
        return Outcome::Pass;
    }
    if Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
        .is_some_and(|host| EXEMPT_HOSTS.contains(&host.as_str()))
    {
        return Outcome::Pass;
    }
    let Some(rule) = matching_rule(rules, page) else {
        return Outcome::Pass;
    };

    let replaced = rule
        .replace
        .iter()
        .find(|(from, _)| url.starts_with(from.as_str()))
        .map(|(from, to)| format!("{to}{}", &url[from.len()..]));
    let url = replaced.clone().unwrap_or_else(|| url.to_owned());

    if is_blocked(rule, &url, page) {
        return Outcome::Block { rule: rule.rule_name.clone() };
    }
    match replaced {
        Some(url) => Outcome::Replace {
            url,
            rule: rule.rule_name.clone(),
            header: rule.add_replace_header,
        },
        None => Outcome::Pass,
    }
}

/// The first rule whose pattern occurs in the page's origin and path. `*`
/// matches every page. A page with no rule has none applied.
fn matching_rule<'a>(rules: &'a [Rule], page: &Url) -> Option<&'a Rule> {
    let key = format!("{}{}", page.origin().ascii_serialization(), page.path());
    rules.iter().find(|rule| {
        rule.url_pattern
            .iter()
            .any(|pattern| pattern == "*" || key.contains(pattern.as_str()))
    })
}

/// Whether the rule's lists refuse `url`. A URL on the page's own origin is
/// refused only when `enableSameOriginBlock` is set; any other origin is
/// refused by a blocklist match.
fn is_blocked(rule: &Rule, url: &str, page: &Url) -> bool {
    let same_origin = url.starts_with(&page.origin().ascii_serialization());
    if rule
        .blocklist
        .iter()
        .any(|entry| url.starts_with(entry.as_str()) && (!same_origin || rule.enable_same_origin_block))
    {
        return true;
    }
    !rule.allowlist.is_empty() && !rule.allowlist.iter().any(|entry| url.starts_with(entry.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Url {
        Url::parse("https://tiktok.com/foryou").unwrap()
    }

    fn rule(json: &str) -> Vec<Rule> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_the_network_file_format() {
        let rules = rule(
            r#"[{"ruleName":"r","urlPattern":["tiktok.com/foryou"],"replace":{"https://a.com/":"https://b.com/"},
                 "allowlist":[],"blocklist":["https://ads.example/"],"enableSameOriginBlock":true,"addReplaceHeader":true}]"#,
        );
        assert_eq!(rules[0].rule_name, "r");
        assert!(rules[0].enable_same_origin_block && rules[0].add_replace_header);
        assert!(rule("[]").is_empty());
    }

    #[test]
    fn replaces_a_prefix() {
        let rules = vec![default_rule()];
        let outcome = apply_rules(&rules, &page(), "https://unpkg.byted-static.com/x/y.js");
        assert_eq!(
            outcome,
            Outcome::Replace {
                url: "https://sf-unpkg.tiktokcdn.com/obj/unpkg-va/x/y.js".into(),
                rule: "default_rule".into(),
                header: false,
            }
        );
    }

    #[test]
    fn blocks_cross_origin_blocklist_matches() {
        let rules = rule(r#"[{"ruleName":"b","urlPattern":["*"],"blocklist":["https://ads.example/"]}]"#);
        assert_eq!(
            apply_rules(&rules, &page(), "https://ads.example/x"),
            Outcome::Block { rule: "b".into() }
        );
        assert_eq!(apply_rules(&rules, &page(), "https://other.example/x"), Outcome::Pass);
    }

    #[test]
    fn same_origin_is_blocked_only_when_enabled() {
        let plain = rule(r#"[{"ruleName":"b","urlPattern":["*"],"blocklist":["https://tiktok.com/api"]}]"#);
        assert_eq!(apply_rules(&plain, &page(), "https://tiktok.com/api/x"), Outcome::Pass);
        let enabled = rule(
            r#"[{"ruleName":"b","urlPattern":["*"],"blocklist":["https://tiktok.com/api"],"enableSameOriginBlock":true}]"#,
        );
        assert!(matches!(apply_rules(&enabled, &page(), "https://tiktok.com/api/x"), Outcome::Block { .. }));
    }

    #[test]
    fn allowlist_refuses_what_it_does_not_name() {
        let rules = rule(r#"[{"ruleName":"a","urlPattern":["*"],"allowlist":["https://ok.example/"]}]"#);
        assert_eq!(apply_rules(&rules, &page(), "https://ok.example/x"), Outcome::Pass);
        assert!(matches!(apply_rules(&rules, &page(), "https://no.example/x"), Outcome::Block { .. }));
    }

    #[test]
    fn a_page_without_a_matching_rule_has_none_applied() {
        let rules = rule(r#"[{"ruleName":"a","urlPattern":["other.com"],"blocklist":["https://ads.example/"]}]"#);
        assert_eq!(apply_rules(&rules, &page(), "https://ads.example/x"), Outcome::Pass);
    }

    #[test]
    fn exempt_pages_and_local_hosts_are_not_processed() {
        let rules = vec![default_rule()];
        let test_page = Url::parse("https://tiktok.com/foryou?is_test_only=1").unwrap();
        assert_eq!(
            apply_rules(&rules, &test_page, "https://unpkg.byted-static.com/x"),
            Outcome::Pass
        );
        assert_eq!(
            apply_rules(&rules, &page(), "http://localhost/unpkg.byted-static.com/x"),
            Outcome::Pass
        );
    }
}
