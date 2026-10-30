//! The admin + OAuth-callback + MCP server: add/list upstreams, fetch a
//! login URL, receive the redirect that completes one, and (`/mcp`) answer
//! MCP itself over Streamable HTTP -- the `service` half of a split
//! mcp-gateway, with [`super::Relay`] as its `stdio` half. Plain HTTP/1.1
//! (JSON in, JSON out) on one port, since a browser's OAuth redirect can
//! only ever be that -- never gRPC -- so there is no separate protocol for
//! the rest of the admin surface to gain by not also being plain HTTP.
//!
//! Routes:
//! - `GET /callback?code=&state=`   the OAuth redirect; see [`Gateway::complete_login`]
//! - `POST /mcp`                    one JSON-RPC message; see [`Gateway::handle`]
//! - `GET /upstreams`               -> `[` [`UpstreamInfo`] as JSON `, ...]`
//! - `POST /upstreams`              an [`Upstream`] as JSON; see [`Gateway::add_upstream`]
//! - `POST /upstreams/<name>/login` -> `{"url": "..."}`; see [`Gateway::begin_login`].
//!   `POST`, not `GET`: it starts a new pending login (a fresh PKCE verifier
//!   and `state`) every time, so it is not safe to prefetch, retry, or cache.
//!
//! One upstream's `oauth.redirect_uri` is only ever disambiguated by the
//! `state` the authorization server echoes back, not by path or port, so
//! every upstream can (and, to share this one listener, should) point its
//! `redirect_uri` at this same `/callback`.
//!
//! `shared_secret`, if given to [`serve`], gates every route except
//! `/callback` behind `Authorization: Bearer <shared_secret>` -- `/callback`
//! cannot carry one, since it is a browser's plain redirect, not a call a
//! caller controls the headers of. Running this on a public address (rather
//! than `127.0.0.1`) without a `shared_secret` hands out every upstream's
//! live credentials to the entire internet.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use serde_json::json;

use super::gateway::Gateway;
use super::login_server::parse_query;
use super::upstream::Upstream;

/// Runs the admin server on `addr` until it fails to bind. Each connection is
/// handled on its own thread; `runtime` drives the async calls a request may
/// need ([`Gateway::complete_login`] and [`Gateway::handle`] itself).
pub fn serve(
    addr: SocketAddr,
    gateway: Arc<Gateway>,
    runtime: Arc<tokio::runtime::Runtime>,
    shared_secret: Option<String>,
) -> std::io::Result<()> {
    let shared_secret = Arc::new(shared_secret);
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let gateway = Arc::clone(&gateway);
        let runtime = Arc::clone(&runtime);
        let shared_secret = Arc::clone(&shared_secret);
        std::thread::spawn(move || handle(stream, &gateway, &runtime, shared_secret.as_deref()));
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: String,
    /// Lowercased names.
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, gateway: &Gateway, runtime: &tokio::runtime::Runtime, shared_secret: Option<&str>) {
    let Some(request) = read_request(&stream) else { return };
    let (status, content_type, body) = route(gateway, runtime, shared_secret, &request);
    respond(&mut stream, status, content_type, &body);
}

/// Reads the request line, headers, and body of one HTTP/1.1 request. `None`
/// on anything malformed or cut short -- the connection is simply dropped,
/// same as a client retry.
fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (path, query) = (path.to_owned(), query.to_owned());

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_owned());
            if name == "content-length" {
                content_length = value.parse().ok()?;
            }
            headers.insert(name, value);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(Request { method, path, query, headers, body })
}

/// The response's status, `content-type`, and body.
fn route(gateway: &Gateway, runtime: &tokio::runtime::Runtime, shared_secret: Option<&str>, request: &Request) -> (u16, &'static str, Vec<u8>) {
    if request.path != "/callback" && !authorized(request, shared_secret) {
        return (401, "text/plain", b"unauthorized".to_vec());
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/callback") => callback(gateway, runtime, &request.query),
        ("POST", "/mcp") => mcp(gateway, runtime, &request.body),
        ("GET", "/upstreams") => list_upstreams(gateway),
        ("POST", "/upstreams") => add_upstream(gateway, &request.body),
        ("POST", path) => match path.strip_prefix("/upstreams/").and_then(|rest| rest.strip_suffix("/login")) {
            Some(name) => login(gateway, name),
            None => (404, "text/plain", b"not found".to_vec()),
        },
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

fn authorized(request: &Request, shared_secret: Option<&str>) -> bool {
    let Some(secret) = shared_secret else { return true };
    request.headers.get("authorization").is_some_and(|value| value == &format!("Bearer {secret}"))
}

fn callback(gateway: &Gateway, runtime: &tokio::runtime::Runtime, query: &str) -> (u16, &'static str, Vec<u8>) {
    let params = parse_query(query);
    let outcome = match (params.get("code"), params.get("state")) {
        (Some(code), Some(state)) => runtime.block_on(gateway.complete_login(state, code)),
        _ => Err(params.get("error").cloned().unwrap_or_else(|| "no code".to_owned())),
    };
    match outcome {
        Ok(name) => (200, "text/plain", format!("Logged in to {name}. You can close this window.").into_bytes()),
        Err(err) => (400, "text/plain", format!("Login failed: {err}").into_bytes()),
    }
}

/// `Gateway::handle`, as the body of one `POST /mcp`. A notification (no
/// `id`, so [`Gateway::handle`] answers `None`) gets `202 Accepted` and no
/// body, the Streamable HTTP convention for "received, nothing to reply".
fn mcp(gateway: &Gateway, runtime: &tokio::runtime::Runtime, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let message = match serde_json::from_slice(body) {
        Ok(message) => message,
        Err(err) => return (400, "application/json", json!({ "error": format!("invalid JSON body: {err}") }).to_string().into_bytes()),
    };
    match runtime.block_on(gateway.handle(message)) {
        Some(reply) => (200, "application/json", serde_json::to_vec(&reply).expect("a JSON value serializes")),
        None => (202, "application/json", Vec::new()),
    }
}

fn list_upstreams(gateway: &Gateway) -> (u16, &'static str, Vec<u8>) {
    let body = serde_json::to_vec(&gateway.list_upstreams()).expect("a JSON value serializes");
    (200, "application/json", body)
}

fn add_upstream(gateway: &Gateway, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let outcome = match serde_json::from_slice::<Upstream>(body) {
        Ok(upstream) => gateway.add_upstream(upstream),
        Err(err) => Err(format!("invalid JSON body: {err}")),
    };
    match outcome {
        Ok(()) => (200, "application/json", b"{}".to_vec()),
        Err(err) => (400, "application/json", json!({ "error": err }).to_string().into_bytes()),
    }
}

fn login(gateway: &Gateway, name: &str) -> (u16, &'static str, Vec<u8>) {
    match gateway.begin_login(name) {
        Ok(url) => (200, "application/json", json!({ "url": url }).to_string().into_bytes()),
        Err(err) => (400, "application/json", json!({ "error": err }).to_string().into_bytes()),
    }
}

fn respond(stream: &mut impl Write, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}
