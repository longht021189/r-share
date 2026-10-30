//! A proxy for `<scheme>://<host>/<path>` requests, for webviews on a custom
//! URL scheme.
//!
//! The webview asks for `<scheme>://tiktok.com/x`; [`handle`] fetches
//! `https://tiktok.com/x` and returns the response, adjusted so that a page
//! served this way keeps working:
//!
//! - cookies: a webview keeps none for a custom scheme, so they live in the
//!   process-wide [`cookie::shared`] jar, which this module reads and writes
//!   directly (persist it with [`cookie::init`]). Cookies that pages write
//!   through `document.cookie` reach it through the proxy's own API;
//! - `https://` URLs in the tags of HTML pages are pointed at the scheme, and
//!   a caller-supplied script is injected to do the same at runtime;
//! - headers whose policy names `https://` origins (CSP, CORP, frame options,
//!   CORS) are dropped, and CORS is answered for the scheme's origins instead;
//! - known ad, tracking and telemetry endpoints are answered with an empty 204
//!   without touching the network;
//! - a page's own `fetch`/`XMLHttpRequest` call to a *different* host under
//!   the scheme (e.g. the page is `tiktok.com`, the call targets
//!   `mcs-sg.tiktokv.com`) arrives disguised as a same-host call instead, the
//!   real target carried in [`CROSS_HOST_MARKER`] -- WKWebView doesn't
//!   reliably allow the real thing no matter what CORS headers the response
//!   carries (see `with_cors`'s doc), so `inject_script/cross-host-fix.ts`
//!   never makes it. [`try_handle`] unwraps the disguise before anything
//!   else runs, so every later stage sees the real target;
//! - the proxy has an API of its own that its injected scripts call (cookies
//!   from `document.cookie`), see [`handle_api`].
//! - a page's WebSockets are opened by the proxy, with the page's real origin
//!   and the jar's cookies, and the page talks to them through requests to
//!   its own host (see `websocket`).
//!
//! What varies between projects is passed in through [`Config`].

mod api;
mod blocklist;
mod hash_replace;
mod html;
mod inject_rules;
mod js;
mod pns_cache;
mod pns_rules;
mod range_cache;
mod websocket;
mod worker_scripts;

pub use api::handle_api;
pub use hash_replace::Replace as HashReplace;
pub use hash_replace::Replacement as HashReplacement;
pub use inject_rules::InjectRule;

use pns_cache::Cached;
use pns_rules::Outcome;
use range_cache::{Slice, Window};

use anyhow::{Context, anyhow};
use http::response::Builder;
use http::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};

use crate::cookie;
use crate::http_client::{self, HttpClient};

/// What varies between projects.
pub struct Config {
    /// The URL scheme the webview requests, e.g. `"htl"`.
    pub scheme: &'static str,
    /// Scripts injected first in the `<head>` of an HTML page whose address
    /// matches a rule (see [`inject_rules::matching`]), after the proxy's
    /// own, so they run before the page's own scripts. None may contain
    /// `</script`. More than one rule may match the same page -- all of them
    /// are injected, in the order listed. Empty injects nothing beyond the
    /// proxy's own API scripts.
    pub inject_scripts: &'static [InjectRule],
    /// The worker-side counterpart of `inject_scripts`: scripts run in a
    /// Worker/SharedWorker's own scope, before the worker's own script.
    /// Matched and combined the same way, except `</script` is no concern
    /// (these are never wrapped in a `<script>` tag), and `__RS_SCHEME__`/
    /// `__RS_WORKER_LOCATION__` are filled in wherever a script mentions them
    /// (see `worker_scripts::scripts`) -- a worker's own scheme and address,
    /// which it can't read off `self.location` itself (every worker this
    /// runs in is loaded from a `blob:` URL). A project whose proxied sites
    /// create Workers needs its own `https://` -> scheme rewrite here, the
    /// same way `inject_scripts` needs one for `window`; nothing is injected
    /// automatically.
    pub worker_inject_scripts: &'static [InjectRule],
    /// Where the PNS request rules are fetched from (see `pns_rules`). `None`
    /// applies only the built-in default rule.
    pub pns_rules_url: Option<&'static str>,
    /// Paths whose body is dumped on every fetch, e.g. a site's worker
    /// script that is worth watching for changes -- each to its own `dir`
    /// (see [`dump_if_new`]). Empty disables this. A project that only wants
    /// this in dev builds leaves the list empty outside of them.
    pub dev_watched_paths: &'static [WatchedPath],
    /// Known-broken resources -- a URL and the SHA-256 hash of the body it
    /// serves -- to serve from another URL instead. A fetched body is only
    /// swapped when both its URL and hash match one of these, so a URL that
    /// starts serving something else again goes untouched. Checked before
    /// the response is cached or rewritten; empty disables this.
    pub hash_replacements: &'static [HashReplacement],
}

/// A path watched for [`Config::dev_watched_paths`].
pub struct WatchedPath {
    pub host: &'static str,
    pub path: &'static str,
    /// The dumped file's name, as [`dump_if_new`] takes it: its extension
    /// decides the file written on disk, and its stem (the part before the
    /// last `.`) becomes part of the written filename, alongside the dump's
    /// own timestamp and the content's hash. Unrelated to `path` -- set it
    /// to whatever name makes the dump recognisable, e.g. `"worker.js"`.
    pub filename: &'static str,
    /// The directory this path's dumps are written into (under its own
    /// `<host>/` subdirectory, as [`dump_if_new`] always adds) -- e.g. a
    /// project's `public/`, so the dump lands somewhere the project already
    /// serves or inspects.
    pub dir: &'static str,
}

/// Response headers that must not reach the webview: hop-by-hop or
/// body-describing headers we invalidate, cookies (kept in the jar), and
/// headers whose policy refers to `https://` origins and would block the
/// scheme's own (CSP, CORP/COOP/COEP, X-Frame-Options, CORS — re-added below).
const DROPPED_HEADERS: &[&str] = &[
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "transfer-encoding",
    "set-cookie",
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-resource-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "x-frame-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
];

/// Hosts whose CDN wants the bare minimum a request can carry: `User-Agent`
/// and nothing else, not even `Referer` (an anti-hotlinking measure,
/// probably meant for TikTok's own `referrerpolicy="no-referrer"` on the
/// `<img>`/`<source>` serving them -- an attribute the webview's
/// custom-scheme requests don't seem to honour, always attaching every
/// other header a real browser would, including the page's real referer).
/// Found by comparing a failing in-app load against a `curl` of the same URL
/// with only `User-Agent` and an empty `Referer`, which succeeded. A host
/// also covers its subdomains.
const MINIMAL_HEADER_HOSTS: &[&str] = &["ibyteimg.com"];

/// Whether `host` only wants `User-Agent` (see [`MINIMAL_HEADER_HOSTS`]).
fn wants_minimal_headers(host: &str) -> bool {
    MINIMAL_HEADER_HOSTS.iter().any(|blocked| blocklist::is_host_or_subdomain(host, blocked))
}

/// The query key a same-host "disguised" cross-host request carries its real
/// target in, as a full, percent-encoded `https://...` URL -- see
/// `try_handle`'s own doc on why a page needs this at all.
///
/// Mirrors `inject_script/cross-host-fix.ts`'s own copy of this string --
/// keep them in sync.
const CROSS_HOST_MARKER: &str = "__rs_x_host";

/// `url`'s [`CROSS_HOST_MARKER`] value, percent-decoded, if it has one.
fn cross_host_target(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.query_pairs().find(|(key, _)| key == CROSS_HOST_MARKER).map(|(_, value)| value.into_owned())
}

/// Answers one request from the webview. Never fails: a request that cannot be
/// served gets a `502` with the reason as its body.
///
/// Upstream requests go through `http`, with the process-wide [`cookie::shared`]
/// jar: each hop gets its cookies, and every `Set-Cookie` is stored, redirects
/// included.
pub async fn handle(config: &Config, http: &HttpClient, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    match try_handle(config, http, &request).await {
        Ok(response) => response,
        Err(err) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("content-type", "text/plain; charset=utf-8")
            .body(format!("{err:#}").into_bytes())
            .expect("a static status and header make a valid response"),
    }
}

async fn try_handle(
    config: &Config,
    http: &HttpClient,
    request: &Request<Vec<u8>>,
) -> anyhow::Result<Response<Vec<u8>>> {
    if let Some(response) = handle_api(config, request) {
        return Ok(response);
    }
    if let Some(response) = websocket::handle(http, request).await {
        return Ok(response);
    }
    // Answer CORS preflights here; the upstream only knows `https://` origins.
    if request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key("access-control-request-method")
    {
        return no_content(request);
    }

    let uri = request.uri();
    let mut host = uri.host().ok_or_else(|| anyhow!("missing host"))?.to_string();
    let mut path_and_query = uri.path_and_query().map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
    let mut url = format!("https://{host}{path_and_query}");

    // WKWebView doesn't reliably allow a page served over this scheme to
    // `fetch`/`XMLHttpRequest` a *different* host under it, no matter what
    // CORS headers the real response carries (see `with_cors`'s own doc for
    // the `Origin` half of this same platform limitation). So
    // `inject_script/cross-host-fix.ts` routes those through the page's own
    // host instead -- same-origin, not subject to the restriction at all --
    // carrying the real target in `CROSS_HOST_MARKER`. Unwrapped first thing,
    // so every stage below (blocklist, PNS rules, caching, headers) sees the
    // real target, not the disguise.
    if let Some(target) = cross_host_target(&url) {
        let target_url = url::Url::parse(&target).context("invalid __rs_x_host target")?;
        host = target_url.host_str().ok_or_else(|| anyhow!("__rs_x_host target has no host"))?.to_string();
        path_and_query =
            format!("{}{}", target_url.path(), target_url.query().map_or_else(String::new, |q| format!("?{q}")));
        url = target;
    }
    let host = host.as_str();
    let path = path_and_query.split('?').next().unwrap_or("/");
    let query = path_and_query.split_once('?').map(|(_, q)| q);

    if blocklist::is_blocked(host, path) {
        return no_content(request);
    }

    // `inject.ts`'s wrapped `Worker`/`SharedWorker` marks a worker script's
    // URL this way to ask that `Config::worker_inject_scripts` run before it.
    // The real server never sees the marker, and the worker's own cache entry
    // (below) is kept separate from a plain fetch of the same URL, since they
    // answer different bodies.
    let wants_worker_scripts = worker_scripts::wants(query);
    if wants_worker_scripts {
        url = worker_scripts::strip_marker(&url);
    }

    // The worker's request rules apply to requests from a page, i.e. one with a
    // `Referer`. They may refuse the request, or fetch another URL instead.
    let mut replaced_by_rule = None;
    let page = request
        .headers()
        .get("referer")
        .and_then(|value| value.to_str().ok())
        .map(|referer| referer.replacen(&format!("{}://", config.scheme), "https://", 1))
        .and_then(|referer| url::Url::parse(&referer).ok());
    if let Some(page) = &page {
        if let Some(rules_url) = config.pns_rules_url {
            pns_rules::refresh(http, rules_url).await;
        }
        match pns_rules::apply(page, &url) {
            Outcome::Pass => {}
            Outcome::Block { .. } => return blocked_response(request),
            Outcome::Replace { url: to, header, .. } => {
                url = to;
                replaced_by_rule = header.then_some(());
            }
        }
    }

    // The worker's GET cache: a marked URL is answered from the cache when it
    // can be, and is kept after a fetch.
    let cache_key = (request.method() == Method::GET && !wants_worker_scripts)
        .then(|| pns_cache::key_of(&url))
        .flatten();
    if let Some(key) = &cache_key {
        if let Some(cached) = pns_cache::get(key, &url) {
            return cached_response(cached, request);
        }
    }

    // A media range is answered from the read-ahead window when that holds it.
    // Otherwise a larger window is fetched, and kept (see `range_cache`).
    let range = (request.method() == Method::GET)
        .then(|| request.headers().get("range")?.to_str().ok())
        .flatten()
        .and_then(range_cache::parse_range);
    if let Some((start, Some(end))) = range {
        let hit = range_cache::cache().get(&url, start, end);
        if let Some(slice) = hit {
            return slice_response(slice, request);
        }
    }
    let window_end = range.map(|(start, end)| range_cache::fetch_end(start, end));

    // A top-level page load (as opposed to a sub-resource fetch), identified
    // by the `Accept` a navigation request carries. The webview's own engine
    // (WebKit) never sends `Sec-Fetch-*` at all -- those are a Chromium
    // feature -- so a site that keys its response (e.g. whether the page's
    // bootstrap config is embedded) on seeing a real browser's navigation
    // headers gets none of them and serves a degraded page instead. Fetch
    // Metadata is synthesized here to match what Chrome sends for a plain,
    // user-initiated top-level navigation.
    let is_document = request.method() == Method::GET
        && request
            .headers()
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"));
    let sec_fetch_site = match page.as_ref().and_then(|page| page.host_str()) {
        Some(referer_host) if referer_host == host => "same-origin",
        Some(_) => "cross-site",
        None => "none",
    };
    let minimal_headers = wants_minimal_headers(host);

    let mut upstream = http_client::Request::new(upstream_method(request.method())?, &url);
    upstream.body = request.body().clone();
    for (name, value) in request.headers() {
        // `cookie` is filled in from the jar, and `accept-encoding` is left to
        // the client so the body is decoded. A window replaces the `range`.
        // `sec-fetch-*` is replaced below for a document load (see
        // `is_document`), rather than whatever -- usually nothing -- the
        // webview itself sent. A host in `MINIMAL_HEADER_HOSTS` gets nothing
        // here but `user-agent`.
        if name == "host"
            || name == "cookie"
            || name == "accept-encoding"
            || (window_end.is_some() && name == "range")
            || (is_document && name.as_str().starts_with("sec-fetch-"))
            || (minimal_headers && name != "user-agent")
        {
            continue;
        }
        let text = String::from_utf8_lossy(value.as_bytes());
        upstream = upstream.header(
            name.as_str(),
            // Servers expect the real origin, not our custom scheme.
            if name == "origin" || name == "referer" {
                text.replacen(&format!("{}://", config.scheme), "https://", 1)
            } else {
                text.into_owned()
            },
        );
    }
    if is_document {
        upstream = upstream
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", sec_fetch_site)
            .header("sec-fetch-user", "?1");
    }
    if let (Some((start, _)), Some(end)) = (range, window_end) {
        upstream = upstream.header("range", format!("bytes={start}-{end}"));
    }
    let mut upstream = http
        .send_with_cookies(cookie::shared(), upstream)
        .await
        .with_context(|| format!("cannot fetch {url}"))?;
    cookie::shared().save();

    // A known-broken body at a known URL is served from its replacement
    // instead. A `Url` replacement swaps the entire response (a failed
    // fetch leaves the original in place rather than failing the request);
    // a `Bytes` replacement only swaps the body, keeping the original
    // status and headers.
    match hash_replace::find(config.hash_replacements, &url, &upstream.body) {
        Some(hash_replace::Replace::Url(replacement_url)) => {
            if let Ok(replaced) = http
                .send_with_cookies(cookie::shared(), http_client::Request::get(*replacement_url))
                .await
            {
                upstream = replaced;
                cookie::shared().save();
            }
        }
        Some(hash_replace::Replace::Bytes(bytes)) => upstream.body = bytes.to_vec(),
        None => {}
    }

    let status = StatusCode::from_u16(upstream.status).context("upstream sent an invalid status")?;
    let mut body = upstream.body;

    let watched = config.dev_watched_paths.iter().find(|w| host == w.host && path == w.path);
    if let Some(w) = watched {
        dump_if_new(w.dir, host, w.filename, &body);
    }

    // The window answers the request: send back exactly the range that was
    // asked for, and keep the window itself only when it is media.
    if let (Some((start, end)), true) = (range, status == StatusCode::PARTIAL_CONTENT) {
        let served = header(&upstream.headers, "content-range").and_then(range_cache::parse_content_range);
        if let Some((first, _, total)) = served.filter(|(first, _, _)| *first == start) {
            if !body.is_empty() {
                let content_type = header(&upstream.headers, "content-type").unwrap_or("application/octet-stream");
                let last = first + body.len() as u64 - 1;
                let end = end.unwrap_or(last).min(last);
                let slice = Slice {
                    start,
                    end,
                    total,
                    content_type: content_type.to_owned(),
                    data: body[..(end - start + 1) as usize].to_vec(),
                };
                if range_cache::is_media(content_type) {
                    range_cache::cache().put(url.clone(), Window::new(first, body, total, content_type.to_owned()));
                }
                return slice_response(slice, request);
            }
        }
    }

    let mut headers: Vec<(String, String)> = upstream
        .headers
        .iter()
        .filter(|(name, _)| !DROPPED_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
        .cloned()
        .collect();
    if replaced_by_rule.is_some() {
        headers.push(("x-pns-replaced".into(), "1".into()));
    }
    if is_html(&upstream.headers) {
        body = html::rewrite(body, config.scheme, &config.scripts(host, path));
    }
    // Dev builds only: removing a real `debugger;` statement is a text-based
    // transform (see `js::strip_debugger`'s own doc), not a real parse, and
    // even its property-name exclusions can't rule out every way it could
    // misread genuinely novel syntax (see git history for one that did). A
    // production build gets the sites' `debugger;`s breakpointing as normal.
    if cfg!(debug_assertions) && (is_html(&upstream.headers) || is_javascript(&upstream.headers)) {
        body = js::strip_debugger(body);
    }
    if wants_worker_scripts {
        // This worker's own address on the proxy's scheme -- not `url` (the
        // upstream fetch address, in `https://`, and possibly rewritten by a
        // PNS rule) -- for `__RS_WORKER_LOCATION__` to resolve to, in case a
        // matching script needs it.
        let worker_location = format!("{}://{host}{path}", config.scheme);
        let scripts = worker_scripts::scripts(config, config.scheme, &worker_location, host, path);
        body = worker_scripts::prepend(body, &scripts);
    }
    if let Some(key) = cache_key {
        if pns_cache::is_cacheable(status.as_u16()) {
            pns_cache::put(
                key,
                Cached { url: url.clone(), status: status.as_u16(), headers: headers.clone(), body: body.clone() },
            );
        }
    }
    build_response(status, &headers, body, request)
}

/// The response for a request refused by a PNS rule, as the worker sends it.
fn blocked_response(request: &Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
    let builder = Response::builder()
        .status(StatusCode::GONE)
        .header("x-pns-blocked", "1")
        .header("content-type", "text/plain; charset=utf-8");
    Ok(with_cors(builder, request).body(b"request blocked".to_vec())?)
}

/// The response for a request answered from the PNS cache.
fn cached_response(cached: Cached, request: &Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
    build_response(StatusCode::from_u16(cached.status)?, &cached.headers, cached.body, request)
}

fn build_response(
    status: StatusCode,
    headers: &[(String, String)],
    body: Vec<u8>,
    request: &Request<Vec<u8>>,
) -> anyhow::Result<Response<Vec<u8>>> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name.as_str(), value.as_str());
    }
    Ok(with_cors(response, request).body(body)?)
}

/// The method to send upstream. Anything else (CONNECT, TRACE, extensions) is
/// refused, as it always was.
fn upstream_method(method: &Method) -> anyhow::Result<http_client::Method> {
    Ok(match *method {
        Method::GET => http_client::Method::Get,
        Method::POST => http_client::Method::Post,
        Method::PUT => http_client::Method::Put,
        Method::PATCH => http_client::Method::Patch,
        Method::DELETE => http_client::Method::Delete,
        Method::HEAD => http_client::Method::Head,
        Method::OPTIONS => http_client::Method::Options,
        _ => return Err(anyhow!("unsupported method {method}")),
    })
}

/// Saves `body` under `<dir>/<host>/<time>-<stem>-<hash>.<ext>`, `time` being
/// the dump's own timestamp (`yyyyMMddHHmmss`) and `stem`/`ext` split out of
/// `filename`, the first time this exact content is seen for `filename` (a
/// directory listing is checked for a `-<stem>-<hash>.<ext>` already there).
/// Filesystem errors are swallowed: this is a debugging aid, not something a
/// request should fail over.
fn dump_if_new(dir: &str, host: &str, filename: &str, body: &[u8]) {
    let hash: String = Sha256::digest(body).iter().map(|byte| format!("{byte:02x}")).collect();
    let (stem, ext) = filename.rsplit_once('.').unwrap_or((filename, ""));
    let suffix = format!("-{stem}-{hash}.{ext}");
    let folder = std::path::Path::new(dir).join(host);
    let already_dumped = std::fs::read_dir(&folder)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .any(|entry| entry.file_name().to_string_lossy().ends_with(&suffix));
    if already_dumped || std::fs::create_dir_all(&folder).is_err() {
        return;
    }
    let time = chrono::Local::now().format("%Y%m%d%H%M%S");
    let _ = std::fs::write(folder.join(format!("{time}{suffix}")), body);
}

fn is_html(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value.starts_with("text/html")
    })
}

fn is_javascript(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && (value.starts_with("text/javascript")
                || value.starts_with("application/javascript")
                || value.starts_with("application/x-javascript"))
    })
}

/// A `206` for part of a cached window, with CORS like every other response.
fn slice_response(slice: Slice, request: &Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
    let total = slice.total.map_or_else(|| "*".to_owned(), |total| total.to_string());
    let builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header("content-type", slice.content_type)
        .header("accept-ranges", "bytes")
        .header("content-range", format!("bytes {}-{}/{total}", slice.start, slice.end));
    Ok(with_cors(builder, request).body(slice.data)?)
}

/// The value of header `name` (case-insensitive), if present.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// An empty `204` that the page's CORS check accepts.
fn no_content(request: &Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
    Ok(with_cors(Response::builder().status(StatusCode::NO_CONTENT), request).body(Vec::new())?)
}

/// Every `<scheme>://` resource is cross-origin to the page (each host is its
/// own origin), so allow it, echoing the caller's origin so credentials still
/// work -- or, lacking that (WKWebView doesn't always attach `Origin` to a
/// cross-origin `fetch`/`XMLHttpRequest` made from a page served over a
/// custom scheme), [`referer_origin`]'s best approximation of it, so a
/// credentialed cross-origin call doesn't fail CORS for the sole reason that
/// the browser left the header out.
fn with_cors(mut builder: Builder, request: &Request<Vec<u8>>) -> Builder {
    let headers = request.headers();
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| referer_origin(headers));
    match origin {
        Some(origin) => {
            builder = builder
                .header("access-control-allow-origin", origin)
                .header("access-control-allow-credentials", "true")
                .header("vary", "origin");
        }
        None => builder = builder.header("access-control-allow-origin", "*"),
    }
    if let Some(method) = headers.get("access-control-request-method") {
        builder = builder.header("access-control-allow-methods", method);
    }
    if let Some(requested) = headers.get("access-control-request-headers") {
        builder = builder.header("access-control-allow-headers", requested);
    }
    builder
}

/// `headers`' `Referer`, as a bare `scheme://host` origin (no path, no
/// trailing slash), if it has one and it parses. Not `Url::origin()`: that
/// treats every scheme but a handful of standard web ones (`http`, `https`,
/// `ws`, `wss`, `ftp`) as opaque, which the proxy's own custom scheme always
/// is, making it useless here.
fn referer_origin(headers: &http::HeaderMap) -> Option<String> {
    let referer = headers.get("referer")?.to_str().ok()?;
    let url = url::Url::parse(referer).ok()?;
    Some(format!("{}://{}", url.scheme(), url.host_str()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: Config = Config {
        scheme: "htl",
        inject_scripts: &[],
        worker_inject_scripts: &[],
        pns_rules_url: None,
        dev_watched_paths: &[],
        hash_replacements: &[],
    };

    fn request(method: Method, uri: &str) -> http::request::Builder {
        Request::builder().method(method).uri(uri)
    }

    fn client() -> HttpClient {
        HttpClient::start().unwrap()
    }

    #[tokio::test]
    async fn answers_a_cors_preflight_without_the_network() {
        let http = client();
        let req = request(Method::OPTIONS, "htl://example.test/api")
            .header("origin", "htl://example.test")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-token")
            .body(Vec::new())
            .unwrap();

        let res = handle(&CONFIG, &http, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let headers = res.headers();
        assert_eq!(headers["access-control-allow-origin"], "htl://example.test");
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(headers["access-control-allow-methods"], "POST");
        assert_eq!(headers["access-control-allow-headers"], "x-token");
    }

    #[tokio::test]
    async fn a_disguised_cross_host_request_is_unwrapped_before_the_blocklist() {
        // The disguise's own host/path (htl://example.test/whatever-here) is
        // same-origin to a page there, so it never trips the CORS wall; the
        // real target (a blocked host) must still be checked against it, not
        // the disguise.
        let http = client();
        let real = "https://mcs-sg.tiktokv.com/v1/list";
        let req = request(
            Method::POST,
            &format!("htl://example.test/whatever-here?__rs_x_host={}", urlencoding_encode(real)),
        )
        .body(b"payload".to_vec())
        .unwrap();

        let res = handle(&CONFIG, &http, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
    }

    #[test]
    fn cross_host_target_decodes_the_marker() {
        let real = "https://mcs-sg.tiktokv.com/v1/list?a=1&b=2";
        let disguised = format!("https://example.test/?__rs_x_host={}", urlencoding_encode(real));
        assert_eq!(cross_host_target(&disguised).as_deref(), Some(real));
    }

    #[test]
    fn cross_host_target_is_none_without_the_marker() {
        assert_eq!(cross_host_target("https://example.test/?a=1"), None);
    }

    /// A tiny, dependency-free `encodeURIComponent`-equivalent, just enough
    /// for the one URL these tests encode (scheme, host, path, `?`/`=`/`&`).
    fn urlencoding_encode(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                    (byte as char).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn blocked_requests_get_an_empty_204() {
        let http = client();
        let req = request(Method::POST, "htl://mcs-sg.tiktokv.com/v1/list")
            .body(b"payload".to_vec())
            .unwrap();

        let res = handle(&CONFIG, &http, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
        assert_eq!(res.headers()["access-control-allow-origin"], "*");
    }

    #[tokio::test]
    async fn falls_back_to_the_referer_s_origin_when_origin_is_missing() {
        // WKWebView doesn't always attach `Origin` to a cross-origin
        // fetch/XHR made from a page served over the proxy's custom scheme
        // (see `with_cors`'s own doc) -- `Referer` is what's left to go on.
        let http = client();
        let req = request(Method::POST, "htl://mcs-sg.tiktokv.com/v1/list")
            .header("referer", "htl://tiktok.com/foryou")
            .body(b"payload".to_vec())
            .unwrap();

        let res = handle(&CONFIG, &http, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let headers = res.headers();
        assert_eq!(headers["access-control-allow-origin"], "htl://tiktok.com");
        assert_eq!(headers["access-control-allow-credentials"], "true");
    }

    #[test]
    fn referer_origin_treats_the_proxy_s_own_scheme_as_a_real_origin() {
        // `Url::origin()` would call this opaque (it only recognises a
        // handful of standard web schemes), which is useless here.
        let mut headers = http::HeaderMap::new();
        headers.insert("referer", "htl://tiktok.com/foryou?a=1".parse().unwrap());
        assert_eq!(referer_origin(&headers).as_deref(), Some("htl://tiktok.com"));
    }

    #[test]
    fn referer_origin_is_none_without_a_parseable_referer() {
        assert!(referer_origin(&http::HeaderMap::new()).is_none());
        let mut headers = http::HeaderMap::new();
        headers.insert("referer", "not a url".parse().unwrap());
        assert!(referer_origin(&headers).is_none());
    }

    #[tokio::test]
    async fn a_request_without_a_host_gets_a_502() {
        let http = client();
        let req = request(Method::GET, "/just-a-path")
            .body(Vec::new())
            .unwrap();

        let res = handle(&CONFIG, &http, req).await;
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(String::from_utf8_lossy(res.body()), "missing host");
    }

    #[test]
    fn wants_minimal_headers_for_a_known_cdn_host_and_its_subdomains() {
        assert!(wants_minimal_headers("ibyteimg.com"));
        assert!(wants_minimal_headers("p21-ad-sg.ibyteimg.com"));
        assert!(!wants_minimal_headers("tiktok.com"));
        assert!(!wants_minimal_headers("notibyteimg.com"));
    }

    #[test]
    fn html_is_recognised_by_content_type() {
        let mut headers = vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())];
        assert!(is_html(&headers));
        headers[0].1 = "application/json".to_string();
        assert!(!is_html(&headers));
        assert!(!is_html(&[]));
    }

    #[test]
    fn javascript_is_recognised_by_content_type() {
        for value in ["text/javascript; charset=utf-8", "application/javascript", "application/x-javascript"] {
            assert!(is_javascript(&[("Content-Type".to_string(), value.to_string())]));
        }
        assert!(!is_javascript(&[("Content-Type".to_string(), "application/json".to_string())]));
        assert!(!is_javascript(&[]));
    }

    #[test]
    fn dump_if_new_writes_once_per_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();

        dump_if_new(dir, "truyen.moe", "imgx-worker.js", b"v1");
        let folder = tmp.path().join("truyen.moe");
        let files = || std::fs::read_dir(&folder).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap());
        let names: Vec<_> = files().collect();
        assert_eq!(names.len(), 1);
        let hash: String = Sha256::digest(b"v1").iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(names[0].ends_with(&format!("-imgx-worker-{hash}.js")));

        // Same content again: no second file.
        dump_if_new(dir, "truyen.moe", "imgx-worker.js", b"v1");
        assert_eq!(files().count(), 1);

        // Different content: a second file, keeping the first.
        dump_if_new(dir, "truyen.moe", "imgx-worker.js", b"v2");
        assert_eq!(files().count(), 2);
    }
}
