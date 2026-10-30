//! WebSockets for proxied pages.
//!
//! A page served over the scheme cannot open its WebSockets itself: the
//! server would see the scheme's `Origin` and none of the cookies in the
//! shared jar, and the scheme cannot carry a connection that stays open. So the
//! injected script replaces `WebSocket` with one that asks the proxy to open
//! the real connection ([`HttpClient::connect_websocket`]), and talks to it
//! through plain requests to the page's own host, marked with [`MARKER`]:
//!
//! | call | answer |
//! |---|---|
//! | `GET ?__rs_ws=open&url=<wss://...>&protocols=<a,b>` | `{"id", "protocol"}` once the server accepted the upgrade, or a `502` `{"error"}` |
//! | `POST ?__rs_ws=send&id=<id>&type=text\|binary`, the message as the body | `204` |
//! | `GET ?__rs_ws=recv&id=<id>` | `{"events": [...]}`: waits up to [`POLL_WAIT`] for at least one |
//! | `GET ?__rs_ws=close&id=<id>&code=<code>&reason=<reason>` | `204` |
//!
//! An event is `{"type": "text", "data": "..."}`, `{"type": "binary", "data":
//! "<base64>"}`, or, last, `{"type": "close", "code", "reason", "error"}`
//! (`error` is `null` after a close handshake). `send`, `recv` and `close` for
//! an id that is unknown -- never opened, already closed, or dropped -- are
//! answered `410`.
//!
//! A WebSocket nobody has polled for [`ABANDONED_AFTER`] (its page is gone) is
//! closed the next time one is opened.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::cookie;
use crate::http_client::{self, HttpClient, WebSocket, WsEvent, WsMessage, WsOptions};

/// The query key that marks a call to this module; its value is the call.
///
/// Mirrors `inject_script/patch-websocket.ts`'s own copy -- keep them in sync.
pub(super) const MARKER: &str = "__rs_ws";

/// How long a `recv` waits for something to happen before answering with no
/// events, so the page polls again.
const POLL_WAIT: Duration = Duration::from_secs(20);

/// How long a WebSocket may go unpolled before it counts as abandoned.
const ABANDONED_AFTER: Duration = Duration::from_secs(120);

/// How long the upgrade may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Headers of the page's request that the upgrade request carries too.
const FORWARDED_HEADERS: &[&str] = &["user-agent", "accept-language"];

/// One WebSocket a page opened.
struct Session {
    socket: WebSocket,
    events: tokio::sync::Mutex<mpsc::UnboundedReceiver<WsEvent>>,
    last_poll: Mutex<Instant>,
}

static SESSIONS: LazyLock<Mutex<HashMap<u64, Arc<Session>>>> = LazyLock::new(Default::default);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Answers `request` if it is a call to this module, or returns `None`.
pub(super) async fn handle(http: &HttpClient, request: &Request<Vec<u8>>) -> Option<Response<Vec<u8>>> {
    let query = request.uri().query()?;
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let call = params.get(MARKER)?;
    let id = || params.get("id").and_then(|id| id.parse::<u64>().ok());
    Some(match call.as_str() {
        "open" => open(http, request, &params).await,
        "send" => send(id(), request, &params),
        "recv" => receive(id()).await,
        "close" => close(id(), &params),
        _ => status(StatusCode::BAD_REQUEST),
    })
}

async fn open(http: &HttpClient, request: &Request<Vec<u8>>, params: &HashMap<String, String>) -> Response<Vec<u8>> {
    prune_abandoned();
    let Some(target) = params.get("url") else {
        return error(StatusCode::BAD_REQUEST, "missing url");
    };
    let Some(page_host) = request.uri().authority() else {
        return error(StatusCode::BAD_REQUEST, "missing host");
    };

    let mut upstream = http_client::Request::get(target.as_str());
    upstream.timeout = HANDSHAKE_TIMEOUT;
    // The page's real origin, not the scheme's.
    upstream = upstream.header("Origin", format!("https://{page_host}"));
    for name in FORWARDED_HEADERS {
        if let Some(value) = request.headers().get(*name).and_then(|value| value.to_str().ok()) {
            upstream = upstream.header(*name, value);
        }
    }
    upstream = upstream.header("Pragma", "no-cache").header("Cache-Control", "no-cache");
    if let Some(protocols) = params.get("protocols").filter(|protocols| !protocols.is_empty()) {
        upstream = upstream.header("Sec-WebSocket-Protocol", protocols.as_str());
    }

    // Compression offered, as the page's own browser would.
    let options = WsOptions { deflate: true };
    match http.connect_websocket(Some(cookie::shared()), upstream, options).await {
        Ok((socket, head, events)) => {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let protocol = head.header_values("sec-websocket-protocol").next().unwrap_or("").to_owned();
            let session = Session {
                socket,
                events: tokio::sync::Mutex::new(events),
                last_poll: Mutex::new(Instant::now()),
            };
            SESSIONS.lock().unwrap().insert(id, Arc::new(session));
            json_response(StatusCode::OK, &json!({ "id": id.to_string(), "protocol": protocol }))
        }
        Err(err) => error(StatusCode::BAD_GATEWAY, &format!("cannot open {target}: {err}")),
    }
}

fn send(id: Option<u64>, request: &Request<Vec<u8>>, params: &HashMap<String, String>) -> Response<Vec<u8>> {
    let Some(session) = session(id) else {
        return status(StatusCode::GONE);
    };
    let body = request.body().clone();
    let message = match params.get("type").map(String::as_str) {
        Some("binary") => WsMessage::Binary(body),
        _ => WsMessage::Text(String::from_utf8_lossy(&body).into_owned()),
    };
    match session.socket.send(&message) {
        Ok(()) => status(StatusCode::NO_CONTENT),
        Err(_) => status(StatusCode::GONE),
    }
}

async fn receive(id: Option<u64>) -> Response<Vec<u8>> {
    let Some(session) = session(id) else {
        return status(StatusCode::GONE);
    };
    *session.last_poll.lock().unwrap() = Instant::now();
    let mut events = session.events.lock().await;

    let mut batch = Vec::new();
    let mut closed = false;
    // Wait for the first event, then take whatever else is already there.
    let first = match tokio::time::timeout(POLL_WAIT, events.recv()).await {
        Ok(Some(event)) => Some(event),
        // The channel ended without a close: report one.
        Ok(None) => Some(WsEvent::Closed(http_client::WsClose {
            code: 1006,
            reason: String::new(),
            error: None,
        })),
        Err(_) => None,
    };
    let mut next = first;
    while let Some(event) = next.take() {
        closed |= matches!(event, WsEvent::Closed(_));
        batch.push(event_json(event));
        if closed {
            break;
        }
        next = events.try_recv().ok();
    }
    drop(events);

    *session.last_poll.lock().unwrap() = Instant::now();
    if let (true, Some(id)) = (closed, id) {
        SESSIONS.lock().unwrap().remove(&id);
    }
    json_response(StatusCode::OK, &json!({ "events": batch }))
}

fn close(id: Option<u64>, params: &HashMap<String, String>) -> Response<Vec<u8>> {
    let Some(session) = session(id) else {
        return status(StatusCode::GONE);
    };
    let code = params.get("code").and_then(|code| code.parse().ok()).unwrap_or(1000);
    let reason = params.get("reason").map_or("", String::as_str);
    // The close itself reaches the page through `recv`, which forgets the
    // session then.
    session.socket.close(code, reason);
    status(StatusCode::NO_CONTENT)
}

fn session(id: Option<u64>) -> Option<Arc<Session>> {
    SESSIONS.lock().unwrap().get(&id?).cloned()
}

/// Forgets (and so closes) every WebSocket nobody polled for
/// [`ABANDONED_AFTER`].
fn prune_abandoned() {
    SESSIONS
        .lock()
        .unwrap()
        .retain(|_, session| session.last_poll.lock().unwrap().elapsed() < ABANDONED_AFTER);
}

fn event_json(event: WsEvent) -> Value {
    match event {
        WsEvent::Message(WsMessage::Text(text)) => json!({ "type": "text", "data": text }),
        WsEvent::Message(WsMessage::Binary(bytes)) => {
            json!({ "type": "binary", "data": base64::engine::general_purpose::STANDARD.encode(bytes) })
        }
        WsEvent::Closed(close) => json!({
            "type": "close",
            "code": close.code,
            "reason": close.reason,
            "error": close.error.map(|err| err.to_string()),
        }),
    }
}

fn json_response(code: StatusCode, value: &Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(value.to_string().into_bytes())
        .expect("a static status and headers make a valid response")
}

fn error(code: StatusCode, message: &str) -> Response<Vec<u8>> {
    json_response(code, &json!({ "error": message }))
}

fn status(code: StatusCode) -> Response<Vec<u8>> {
    Response::builder()
        .status(code)
        .header("cache-control", "no-store")
        .body(Vec::new())
        .expect("a static status makes a valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str) -> Request<Vec<u8>> {
        Request::builder().uri(uri).body(Vec::new()).unwrap()
    }

    #[tokio::test]
    async fn requests_without_the_marker_are_not_calls() {
        let http = HttpClient::start().unwrap();
        assert!(handle(&http, &request("htl://chat.zalo.me/?other=1")).await.is_none());
        assert!(handle(&http, &request("htl://chat.zalo.me/")).await.is_none());
    }

    #[tokio::test]
    async fn calls_for_an_unknown_id_are_gone() {
        let http = HttpClient::start().unwrap();
        for uri in [
            "htl://a.example/?__rs_ws=send&id=999999",
            "htl://a.example/?__rs_ws=recv&id=999999",
            "htl://a.example/?__rs_ws=close&id=999999",
            "htl://a.example/?__rs_ws=recv",
        ] {
            let response = handle(&http, &request(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::GONE, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_failed_open_is_a_bad_gateway_with_the_reason() {
        let http = HttpClient::start().unwrap();
        let response = handle(&http, &request("htl://a.example/?__rs_ws=open&url=ws%3A%2F%2F127.0.0.1%3A1%2F"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert!(body["error"].as_str().unwrap().contains("ws://127.0.0.1:1/"), "{body}");
    }

    fn json_body(response: &Response<Vec<u8>>) -> Value {
        serde_json::from_slice(response.body()).unwrap()
    }

    /// Receives until `count` events have arrived.
    async fn receive_events(http: &HttpClient, id: &str, count: usize) -> Vec<Value> {
        let mut events = Vec::new();
        while events.len() < count {
            let response = handle(http, &request(&format!("htl://page.example/?__rs_ws=recv&id={id}")))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            events.extend(json_body(&response)["events"].as_array().unwrap().iter().cloned());
        }
        events
    }

    #[tokio::test]
    async fn a_page_opens_uses_and_closes_a_websocket_through_the_proxy() {
        let http = HttpClient::start().unwrap();
        let (url, upgrades) = crate::http_client::tests::serve_websocket();
        let open_uri = format!(
            "htl://page.example/?__rs_ws=open&url={}&protocols=chat",
            url::form_urlencoded::byte_serialize(format!("{url}/socket").as_bytes()).collect::<String>()
        );
        let open = Request::builder()
            .uri(open_uri)
            .header("user-agent", "TestAgent/1")
            .body(Vec::new())
            .unwrap();

        let response = handle(&http, &open).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let id = json_body(&response)["id"].as_str().unwrap().to_owned();
        let upgrade = upgrades.recv().unwrap();
        assert!(upgrade.contains("Origin: https://page.example"), "{upgrade}");
        assert!(upgrade.contains("user-agent: TestAgent/1"), "{upgrade}");
        assert!(upgrade.contains("Sec-WebSocket-Protocol: chat"), "{upgrade}");

        let send = |kind: &str, body: &[u8]| {
            Request::builder()
                .method("POST")
                .uri(format!("htl://page.example/?__rs_ws=send&id={id}&type={kind}"))
                .body(body.to_vec())
                .unwrap()
        };
        assert_eq!(handle(&http, &send("text", b"hi")).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(handle(&http, &send("binary", &[1, 2, 3])).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(
            receive_events(&http, &id, 3).await,
            [
                json!({ "type": "text", "data": "welcome" }),
                json!({ "type": "text", "data": "hi" }),
                json!({ "type": "binary", "data": "AQID" }),
            ]
        );

        let close = request(&format!("htl://page.example/?__rs_ws=close&id={id}&code=4001&reason=done"));
        assert_eq!(handle(&http, &close).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(
            receive_events(&http, &id, 1).await,
            [json!({ "type": "close", "code": 4001, "reason": "done", "error": null })]
        );
        // Closed, so forgotten.
        let gone = request(&format!("htl://page.example/?__rs_ws=recv&id={id}"));
        assert_eq!(handle(&http, &gone).await.unwrap().status(), StatusCode::GONE);
    }

    #[test]
    fn events_are_json() {
        assert_eq!(
            event_json(WsEvent::Message(WsMessage::Binary(vec![1, 2, 3]))),
            json!({ "type": "binary", "data": "AQID" })
        );
        assert_eq!(
            event_json(WsEvent::Closed(http_client::WsClose {
                code: 1000,
                reason: "bye".into(),
                error: None
            })),
            json!({ "type": "close", "code": 1000, "reason": "bye", "error": null })
        );
    }
}
