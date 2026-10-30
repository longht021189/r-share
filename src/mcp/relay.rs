//! A stdio<->HTTP relay: forwards each JSON-RPC message from stdin verbatim
//! to one remote Streamable-HTTP MCP endpoint, and writes its reply back to
//! stdout verbatim. The `stdio` half of a split mcp-gateway: the `service`
//! half (see [`super::admin`]'s `/mcp` route) already speaks full MCP (merged
//! upstreams, tool-name prefixes and all), so unlike [`super::Gateway`],
//! `Relay` understands none of that -- it is a dumb pipe, trusting the
//! remote end entirely.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use super::{INTERNAL_ERROR, PARSE_ERROR};
use super::transport::sse_messages;
use crate::http_client::{HttpClient, Method, Request, Response};

pub struct Relay {
    http: HttpClient,
    url: String,
    /// Sent with every forwarded request, e.g. the shared secret that
    /// authenticates this relay to the service (`Authorization: Bearer ...`).
    headers: Vec<(String, String)>,
}

impl Relay {
    pub fn new(http: HttpClient, url: String, headers: Vec<(String, String)>) -> Relay {
        Relay { http, url, headers }
    }

    /// Forwards `message` as-is and returns the remote's reply as-is. A
    /// notification (no `id`) is still forwarded, but -- same as
    /// [`super::Gateway::handle`] -- answered with `None` regardless of how
    /// the remote actually answered it.
    pub async fn forward(&self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let outcome = self.send(&message).await;
        let id = id?;
        Some(match outcome.and_then(|response| reply_message(&response, &id)) {
            Ok(reply) => reply,
            Err(err) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": INTERNAL_ERROR, "message": err } }),
        })
    }

    async fn send(&self, message: &Value) -> Result<Response, String> {
        let mut request = Request::new(Method::Post, self.url.as_str());
        request.body = serde_json::to_vec(message).expect("a JSON value serializes");
        request = request
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        self.http.send(request).await.map_err(|err| err.to_string())
    }
}

/// Runs `relay` over stdin/stdout: one JSON message per line in, one per
/// line out, each forwarded to the remote end via [`Relay::forward`].
/// Returns when stdin closes. Mirrors [`super::serve_stdio`], for [`Gateway`](super::Gateway).
pub fn serve_stdio(relay: &Relay, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => runtime.block_on(relay.forward(message)),
            Err(err) => Some(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": PARSE_ERROR, "message": err.to_string() },
            })),
        };
        if let Some(reply) = reply {
            serde_json::to_writer(&mut stdout, &reply)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// The message addressed to `id` in `response`'s JSON or SSE body, as a
/// whole JSON-RPC envelope (result or error) -- unlike
/// [`super::transport::reply_for`], there is no `result` to unwrap: the
/// remote's reply is already exactly what the original caller expects.
fn reply_message(response: &Response, id: &Value) -> Result<Value, String> {
    let text = String::from_utf8_lossy(&response.body);
    if !(200..300).contains(&response.status) {
        let excerpt: String = text.chars().take(200).collect();
        return Err(format!("HTTP {}: {excerpt}", response.status));
    }
    let is_sse = response.header_values("content-type").any(|value| value.starts_with("text/event-stream"));
    if !is_sse {
        return serde_json::from_str(&text).map_err(|err| err.to_string());
    }
    sse_messages(&text)
        .into_iter()
        .find(|message| message.get("id") == Some(id))
        .ok_or_else(|| "no reply to the request".to_owned())
}
