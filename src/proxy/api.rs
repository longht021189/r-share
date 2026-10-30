//! The proxy's own API: hosts under the scheme that are answered here instead
//! of being fetched from the network.
//!
//! Each endpoint answers on the host `<scheme>-<name>`, and comes with a script
//! that the proxy injects into every HTML page (before the caller's own), so
//! pages need no support for it. Every call is answered with `204`.
//!
//! | endpoint | call | effect |
//! |---|---|---|
//! | `cookie` | `?u=<host>&c=<cookie>` | stores `<cookie>`, a `Set-Cookie` style string as page script writes through `document.cookie`, in the shared jar for the page host `<host>` |
//!

//! These requests are answered by [`handle_api`], which is synchronous on
//! purpose: a caller that runs it as soon as a request arrives, before spawning
//! [`handle`](super::handle) for the rest, knows the jar is updated before any
//! request that the page makes afterwards, e.g. a `location.reload()` right
//! after the `document.cookie` write.
//!
//! To add an endpoint, write its handler and its script and add a line to
//! `ENDPOINTS`.

use http::{Request, Response, StatusCode};

use super::Config;
use super::inject_rules;
use crate::cookie;

/// One endpoint of the API.
struct Endpoint {
    /// It answers on the host `<scheme>-<name>`.
    name: &'static str,
    /// The script that calls it. `__ENDPOINT__` in it is replaced with the URL
    /// of the endpoint.
    script: &'static str,
    /// Handles a call, given its URL for the query string.
    handle: fn(&url::Url),
}

const ENDPOINTS: &[Endpoint] = &[Endpoint {
    name: "cookie",
    script: include_str!("cookie_bridge.js"),
    handle: store_cookie,
}];

fn endpoint_host(scheme: &str, endpoint: &Endpoint) -> String {
    format!("{scheme}-{}", endpoint.name)
}

impl Config {
    /// The scripts injected into an HTML page served for `host`/`path`, in
    /// order: those of the proxy's own API (unconditional), then every rule
    /// of `inject_scripts` that matches (see [`inject_rules::matching`]).
    pub(super) fn scripts(&self, host: &str, path: &str) -> Vec<String> {
        let mut scripts: Vec<String> = ENDPOINTS
            .iter()
            .map(|endpoint| {
                let url = format!(
                    "{}://{}/",
                    self.scheme,
                    endpoint_host(self.scheme, endpoint)
                );
                endpoint.script.replace("__ENDPOINT__", &url)
            })
            .collect();
        scripts.extend(inject_rules::matching(self.inject_scripts, host, path).map(str::to_string));
        scripts
    }
}

/// Answers a request for one of the proxy's own API hosts right away, or
/// returns `None` if the request is for anything else, which [`handle`] then
/// fetches. [`handle`] calls this first too, so using it is only needed for the
/// ordering guarantee described in the module docs.
///
/// [`handle`]: super::handle
pub fn handle_api(config: &Config, request: &Request<Vec<u8>>) -> Option<Response<Vec<u8>>> {
    let host = request.uri().host()?;
    let endpoint = ENDPOINTS
        .iter()
        .find(|endpoint| host == endpoint_host(config.scheme, endpoint))?;
    let path_and_query = request.uri().path_and_query().map_or("/", |p| p.as_str());
    if let Ok(query) = url::Url::parse(&format!("http://{host}{path_and_query}")) {
        (endpoint.handle)(&query);
    }
    Some(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Vec::new())
            .expect("a static status makes a valid response"),
    )
}

fn store_cookie(query: &url::Url) {
    let (mut page, mut cookie) = (None, None);
    for (key, value) in query.query_pairs() {
        match &*key {
            "u" => page = Some(value.into_owned()),
            "c" => cookie = Some(value.into_owned()),
            _ => {}
        }
    }
    let (Some(page), Some(mut cookie)) = (page, cookie) else {
        return;
    };
    // The page is served from one host but its requests are redirected across
    // subdomains (tiktok.com -> www.tiktok.com), so make the cookie a domain one.
    if !cookie.to_ascii_lowercase().contains("domain=") {
        cookie.push_str(&format!("; Domain={page}"));
    }
    let Ok(url) = url::Url::parse(&format!("https://{page}/")) else {
        return;
    };
    let jar = cookie::shared();
    // Like a browser, the jar refuses cookies whose domain does not fit the page.
    let _ = jar.add(&cookie, &url);
    jar.save();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: Config = Config {
        scheme: "htl",
        inject_scripts: &[inject_rules::InjectRule { host: "", path_prefix: "", script: "window.mine = 1;" }],
        worker_inject_scripts: &[],
        pns_rules_url: None,
        dev_watched_paths: &[],
        hash_replacements: &[],
    };

    fn request(uri: &str) -> Request<Vec<u8>> {
        Request::builder().uri(uri).body(Vec::new()).unwrap()
    }

    fn cookies_for(url: &str) -> Option<String> {
        cookie::shared().request_header(&url::Url::parse(url).unwrap())
    }

    #[test]
    fn a_cookie_write_lands_in_the_shared_jar() {
        let req = request("htl://htl-cookie/?u=bridge.example.com&c=id%3Dabc%3B%20Max-Age%3D3600");
        let res = handle_api(&CONFIG, &req).unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
        // Written without a `Domain`, so it is widened to the page's domain and
        // reaches its subdomains, as after a `tiktok.com` -> `www.tiktok.com`
        // redirect.
        assert_eq!(
            cookies_for("https://www.bridge.example.com/").as_deref(),
            Some("id=abc")
        );
    }

    #[test]
    fn a_cookie_for_another_domain_is_refused() {
        let req = request(
            "htl://htl-cookie/?u=refused.example.com&c=a%3D1%3B%20Domain%3Dother.example.org",
        );
        assert!(handle_api(&CONFIG, &req).is_some());
        assert_eq!(cookies_for("https://other.example.org/"), None);
    }

    #[test]
    fn a_malformed_call_is_answered_and_ignored() {
        let req = request("htl://htl-cookie/?c=a%3D1");
        assert_eq!(
            handle_api(&CONFIG, &req).unwrap().status(),
            StatusCode::NO_CONTENT
        );
    }

    #[test]
    fn other_hosts_are_not_the_api() {
        assert!(handle_api(&CONFIG, &request("htl://tiktok.com/")).is_none());
        // The API hosts are named after the scheme and the endpoint.
        assert!(handle_api(&CONFIG, &request("htl://other-cookie/")).is_none());
        assert!(handle_api(&CONFIG, &request("htl://htl-other/")).is_none());
        assert!(handle_api(&CONFIG, &request("/no-host")).is_none());
    }

    #[test]
    fn scripts_come_in_order_and_know_their_endpoint() {
        let scripts = CONFIG.scripts("tiktok.com", "/");
        assert_eq!(scripts.len(), 2);
        assert!(scripts[0].contains("'htl://htl-cookie/'"));
        assert_eq!(scripts[1], "window.mine = 1;");

        let without = Config {
            inject_scripts: &[],
            ..CONFIG
        };
        assert_eq!(without.scripts("tiktok.com", "/").len(), 1);
        for script in without.scripts("tiktok.com", "/") {
            assert!(!script.contains("__ENDPOINT__"));
        }
    }

    #[test]
    fn more_than_one_rule_can_match_the_same_page() {
        let config = Config {
            inject_scripts: &[
                inject_rules::InjectRule { host: "", path_prefix: "", script: "base();" },
                inject_rules::InjectRule { host: "tiktok.com", path_prefix: "", script: "tiktok_only();" },
                inject_rules::InjectRule { host: "mapgenie.io", path_prefix: "", script: "mapgenie_only();" },
            ],
            ..CONFIG
        };
        let scripts = config.scripts("tiktok.com", "/foo");
        // The cookie endpoint's script, then both rules that match tiktok.com.
        assert_eq!(scripts.len(), 3);
        assert_eq!(scripts[1], "base();");
        assert_eq!(scripts[2], "tiktok_only();");
    }
}
