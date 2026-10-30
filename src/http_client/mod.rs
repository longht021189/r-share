//! An async HTTP client backed by c-share's `http` module (libcurl, driven by
//! c-share's waker rather than `curl_multi_poll`; see
//! `c-share/modules/http/README.md`). Only built with the `c_share_http`
//! feature.
//!
//! c-share's `Client::run` wants a thread of its own, so one event-loop thread
//! runs for the whole process; [`send`] hands a request to it and resolves
//! when it completes. Like the `reqwest` client in `proxy`, the shared client
//! is never torn down: it lives as long as the process.
//!
//! This is only the transport layer, as in c-share: an HTTP 4xx/5xx is an
//! `Ok` [`Response`] (check [`Response::status`]), and there is no retry or
//! cache. [`send`]/[`send_streaming`] also do nothing with cookies
//! themselves -- unlike `reqwest` (used in [`proxy`](crate::proxy), via its
//! `CookieStore`), c-share::http has no cookie jar of its own, so a plain
//! `send` neither attaches a `Cookie` header nor absorbs a response's
//! `Set-Cookie` ones. [`send_with_cookies`]/[`send_streaming_with_cookies`]
//! do both, against any [`crate::cookie::PersistentJar`] (typically
//! [`crate::cookie::shared`]).
//!
//! [`HttpClient::connect_websocket`] opens a WebSocket over the same libcurl
//! (and so the same TLS stack) as every request.

mod ffi;

use std::fmt;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::cookie::PersistentJar;

/// The HTTP method of a [`Request`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    #[default]
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// One request to [`send`].
#[derive(Clone, Debug)]
pub struct Request {
    pub url: String,
    pub method: Method,
    /// Sent in this order; a name may repeat.
    pub headers: Vec<(String, String)>,
    /// Sent for `Post`/`Put`/`Patch`, and for `Delete` if non-empty; ignored
    /// for `Get`/`Head`/`Options`.
    pub body: Vec<u8>,
    /// Zero means no timeout.
    pub timeout: Duration,
    /// Optional public-key pinning, forwarded to libcurl's
    /// `CURLOPT_PINNEDPUBLICKEY`: a file path, or `sha256//<base64-hash>`
    /// entries separated by `;`. A mismatch fails with
    /// [`ErrorCode::TlsError`]. `None` is normal CA validation.
    pub pinned_public_key: Option<String>,
}

impl Request {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method,
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(30),
            pinned_public_key: None,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }

    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            ..Self::new(Method::Post, url)
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A completed exchange. The body is already decompressed, and the headers
/// are those of the final hop after redirects (followed automatically, up to
/// 10).
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    /// In the order received; a name may repeat (e.g. `Set-Cookie`).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The values of the header `name`, matched case-insensitively.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The status/headers of a [`send_streaming`] response -- everything
/// [`Response`] carries except the body, which goes through that call's
/// `on_chunk` instead.
#[derive(Clone, Debug)]
pub struct ResponseHead {
    pub status: u16,
    /// In the order received; a name may repeat (e.g. `Set-Cookie`).
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// The values of the header `name`, matched case-insensitively.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Why a request failed at the transport level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidUrl,
    CouldNotResolveHost,
    CouldNotConnect,
    TlsError,
    Timeout,
    /// Cancelled, e.g. because the [`send`] future was dropped.
    Aborted,
    /// Anything else; see [`Error::message`].
    TransportError,
    /// The request could not even be handed to the client.
    SubmitFailed,
}

/// A transport-level failure: DNS, connect, TLS, timeout, or cancellation.
/// An HTTP error status is not one -- see [`Response::status`].
#[derive(Clone, Debug)]
pub struct Error {
    pub code: ErrorCode,
    /// For logs; not meant to be parsed.
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// A WebSocket data message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsMessage {
    /// A text message. Invalid UTF-8 from the server is replaced, as
    /// [`String::from_utf8_lossy`] does.
    Text(String),
    Binary(Vec<u8>),
}

/// How [`HttpClient::connect_websocket`] opens a WebSocket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WsOptions {
    /// Offer permessage-deflate, as browsers do: if the server accepts, every
    /// message is compressed both ways (c-share then frames the connection
    /// itself, since libcurl's WebSocket support takes no compressed frame).
    /// If it declines, messages just go uncompressed.
    pub deflate: bool,
}

/// How a WebSocket ended.
#[derive(Clone, Debug)]
pub struct WsClose {
    /// The close frame's code (1005 if it had none), or 1006 if the
    /// connection ended without one.
    pub code: u16,
    pub reason: String,
    /// `None` after a close handshake from either side; otherwise what went
    /// wrong, e.g. the connection dropped.
    pub error: Option<Error>,
}

/// What an open [`WebSocket`] reports, in order. [`WsEvent::Closed`] is the
/// last one, after which the channel ends.
#[derive(Clone, Debug)]
pub enum WsEvent {
    Message(WsMessage),
    Closed(WsClose),
}

/// The code a [`WebSocket`] that is dropped while still open closes with:
/// RFC 6455's "going away".
const WS_GOING_AWAY: u16 = 1001;

/// An open WebSocket, from [`HttpClient::connect_websocket`]. What it
/// receives comes through the event channel returned alongside it. Dropping
/// it closes the connection with code 1001, if it is still open.
pub struct WebSocket {
    client: Arc<ffi::Client>,
    handle: u64,
}

impl WebSocket {
    /// Queues `message`; messages go out in the order they were queued. Fails
    /// once the WebSocket is closed or closing.
    pub fn send(&self, message: &WsMessage) -> Result<(), Error> {
        if self.client.ws_send(self.handle, message) {
            Ok(())
        } else {
            Err(Error {
                code: ErrorCode::TransportError,
                message: "the WebSocket is closed".into(),
            })
        }
    }

    /// Closes the WebSocket with `code` and `reason` (at most 123 bytes) once
    /// the messages queued before it are out; [`WsEvent::Closed`] follows with
    /// them. A no-op if it is already closed or closing.
    pub fn close(&self, code: u16, reason: &str) {
        self.client.ws_close(self.handle, code, reason);
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        self.close(WS_GOING_AWAY, "");
    }
}

impl fmt::Debug for WebSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket").field("handle", &self.handle).finish()
    }
}

/// How many redirects are followed before giving up -- reqwest's default.
const MAX_REDIRECTS: usize = 10;

/// Headers describing a request body. Dropped with the body when a redirect
/// turns the request into a GET.
const PAYLOAD_HEADERS: [&str; 4] = ["content-type", "content-length", "content-encoding", "transfer-encoding"];

/// Headers carrying credentials or a session. Dropped when a redirect leaves
/// the origin -- the same set reqwest drops.
const SENSITIVE_HEADERS: [&str; 5] = ["authorization", "cookie", "cookie2", "proxy-authorization", "www-authenticate"];

type HeadFn = Box<dyn FnOnce(&ResponseHead) -> ControlFlow<()> + Send>;
type ChunkFn = Box<dyn FnMut(&[u8]) -> ControlFlow<()> + Send>;

/// What one redirect chain shares across its hops.
struct Chain {
    /// The jar to send cookies from and store them into, if any.
    jar: Option<&'static PersistentJar>,
    /// Taken by the final hop's head callback. A redirect hop never gets there.
    on_head: Mutex<Option<HeadFn>>,
    on_chunk: Mutex<ChunkFn>,
    /// Set by a redirect hop's head callback just before it aborts that hop:
    /// the redirect's status and Location.
    redirect: Mutex<Option<(u16, String)>>,
}

/// The HTTP client: a cheap, cloneable handle to one c-share event loop.
///
/// Start one at app start and share clones with everything that sends. The
/// loop stops when the last clone is dropped, or earlier if [`shutdown`] is
/// called. A request already in flight keeps the loop alive until it
/// finishes, so neither a shutdown nor a drop cuts a transfer short; a request
/// started after a shutdown fails with [`ErrorCode::SubmitFailed`].
///
/// [`shutdown`]: HttpClient::shutdown
#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<Mutex<Option<Arc<ffi::Client>>>>,
}

impl HttpClient {
    /// Starts the client and its event-loop thread.
    pub fn start() -> Result<HttpClient, Error> {
        let client = ffi::Client::start().ok_or_else(|| Error {
            code: ErrorCode::TransportError,
            message: "c-share could not start the http client".into(),
        })?;
        Ok(HttpClient {
            inner: Arc::new(Mutex::new(Some(Arc::new(client)))),
        })
    }

    /// Stops the event loop, once the requests already in flight have finished.
    /// Safe to call more than once. Must not be called from inside a callback
    /// of a request sent through this client.
    pub fn shutdown(&self) {
        self.inner.lock().unwrap().take();
    }

    /// Sends `request` and resolves once it completes, following redirects.
    /// Dropping the returned future cancels the request.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        self.send_buffered(None, request).await
    }

    /// Like [`send`](Self::send), but streams the response body through `on_chunk` as it
    /// arrives instead of buffering the whole thing in memory -- use this for
    /// large downloads.
    ///
    /// Redirects are followed, and `on_head`/`on_chunk` see only the final
    /// response. `on_head` gets its status and headers as soon as they have
    /// arrived, before any body data, so it can decide early -- e.g. reject a
    /// non-2xx status -- without waiting for the transfer to finish. Returning
    /// [`ControlFlow::Break`] from it aborts the transfer before a single body
    /// byte is read. It is called at most once, and not at all if the request
    /// fails before any headers arrive.
    ///
    /// `on_head` and `on_chunk` run synchronously on c-share's single event-loop
    /// thread (shared across every in-flight request), so keep them fast and
    /// non-blocking -- push into a channel or write to an already-open file,
    /// rather than anything that could stall. Do not capture an [`HttpClient`]
    /// in them: the last handle must not be dropped on the loop thread. Returning
    /// [`ControlFlow::Break`] from `on_chunk` aborts the transfer; the returned
    /// future then resolves to `Err` with [`ErrorCode::Aborted`]. Dropping the
    /// returned future also cancels the request, same as [`send`](Self::send).
    ///
    /// The returned [`ResponseHead`] is still delivered on completion, with the
    /// same status/headers `on_head` saw.
    pub async fn send_streaming(
        &self,
        request: Request,
        on_head: impl FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
        on_chunk: impl FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
    ) -> Result<ResponseHead, Error> {
        self.run_chain(None, request, Box::new(on_head), Box::new(on_chunk)).await
    }

    /// Like [`send`](Self::send), but against `jar`: attaches its `Cookie` header for
    /// each hop's URL before sending, and feeds every response's `Set-Cookie` --
    /// redirects included -- into `jar` as it arrives: the two halves of what
    /// `reqwest`'s `cookie_provider` does automatically for every request.
    ///
    /// A `Cookie` header in `request.headers` is kept as the caller's own, and
    /// the jar's is only added when there is none, as reqwest does.
    ///
    /// Fails with [`ErrorCode::InvalidUrl`] if `request.url` doesn't parse.
    pub async fn send_with_cookies(&self, jar: &'static PersistentJar, request: Request) -> Result<Response, Error> {
        self.send_buffered(Some(jar), request).await
    }

    /// Like [`send_streaming`](Self::send_streaming), but with [`send_with_cookies`](Self::send_with_cookies)'s
    /// cookie-jar behavior. Each response's `Set-Cookie` values go into `jar` as
    /// soon as its headers arrive -- before `on_head` runs, and before any body
    /// byte -- so a cookie is already in the jar even if `on_head` or `on_chunk`
    /// aborts the transfer.
    pub async fn send_streaming_with_cookies(
        &self,
        jar: &'static PersistentJar,
        request: Request,
        on_head: impl FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
        on_chunk: impl FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
    ) -> Result<ResponseHead, Error> {
        self.run_chain(Some(jar), request, Box::new(on_head), Box::new(on_chunk)).await
    }

    /// Opens a WebSocket to `request.url` (`ws://` or `wss://`), resolving
    /// once the server has accepted the upgrade, with its 101 response.
    /// `request.headers` go with the upgrade request -- e.g. `Origin`,
    /// `User-Agent`, `Sec-WebSocket-Protocol`; a `Sec-WebSocket-Extensions` is
    /// replaced by what `options` offers -- and `request.timeout` bounds the
    /// handshake. Redirects are not followed.
    ///
    /// With `jar`, the upgrade carries its cookies for the URL (as its
    /// `http(s)://` counterpart), unless `request` has a `Cookie` header of
    /// its own, and the 101's `Set-Cookie` go into it.
    ///
    /// Fails if the upgrade is refused (the HTTP status is in the message) or
    /// the connection fails. Dropping the returned future aborts the handshake.
    pub async fn connect_websocket(
        &self,
        jar: Option<&'static PersistentJar>,
        mut request: Request,
        options: WsOptions,
    ) -> Result<(WebSocket, ResponseHead, mpsc::UnboundedReceiver<WsEvent>), Error> {
        let url = parse_url(&request.url)?;
        let cookie_url = websocket_cookie_url(&url)?;
        if let Some(jar) = jar {
            let has_cookie = request.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("cookie"));
            if let (false, Some(cookie)) = (has_cookie, jar.request_header(&cookie_url)) {
                request.headers.push(("Cookie".into(), cookie));
            }
        }

        let client = self.client()?;
        let (handle, opened, events) = client.open_websocket(&request, options)?;
        // Aborts the handshake if this future is dropped before it is done;
        // from then on, the `WebSocket` closes the connection when dropped.
        let mut abort = CloseOnDrop {
            client: client.clone(),
            handle,
            done: false,
        };
        let head = opened.await.unwrap_or_else(|_| {
            Err(Error {
                code: ErrorCode::TransportError,
                message: "the WebSocket callbacks were dropped without running".into(),
            })
        });
        abort.done = true;
        let head = head?;
        if let Some(jar) = jar {
            absorb_set_cookie(jar, &cookie_url, &head.headers);
        }
        Ok((WebSocket { client, handle }, head, events))
    }

    fn client(&self) -> Result<Arc<ffi::Client>, Error> {
        self.inner.lock().unwrap().clone().ok_or_else(|| Error {
            code: ErrorCode::SubmitFailed,
            message: "the http client has been shut down".into(),
        })
    }

    async fn send_buffered(&self, jar: Option<&'static PersistentJar>, request: Request) -> Result<Response, Error> {
        let body = Arc::new(Mutex::new(Vec::<u8>::new()));
        let collected = body.clone();
        let head = self
            .run_chain(
                jar,
                request,
                Box::new(|_: &ResponseHead| ControlFlow::Continue(())),
                Box::new(move |chunk: &[u8]| {
                    collected.lock().unwrap().extend_from_slice(chunk);
                    ControlFlow::Continue(())
                }),
            )
            .await?;
        let body = std::mem::take(&mut *body.lock().unwrap());
        Ok(Response {
            status: head.status,
            headers: head.headers,
            body,
        })
    }

    /// Runs `request` to its final response, following redirects the way reqwest
    /// does by default. Each hop is one c-share request that is aborted from its
    /// head callback as soon as it turns out to be a redirect, so the redirect's
    /// body is never read and `on_head`/`on_chunk` only ever see the final hop.
    async fn run_chain(
        &self,
        jar: Option<&'static PersistentJar>,
        mut request: Request,
        on_head: HeadFn,
        on_chunk: ChunkFn,
    ) -> Result<ResponseHead, Error> {
        let mut current = parse_url(&request.url)?;
        let chain = Arc::new(Chain {
            jar,
            on_head: Mutex::new(Some(on_head)),
            on_chunk: Mutex::new(on_chunk),
            redirect: Mutex::new(None),
        });
        let mut previous: Option<url::Url> = None;
        let mut redirects = 0;
        loop {
            let mut hop = request.clone();
            hop.url = current.to_string();
            if let Some(previous) = &previous {
                remove_sensitive_headers(&mut hop.headers, &current, previous);
                set_referer(&mut hop.headers, &current, previous);
            }
            if let Some(jar) = jar {
                let has_cookie = hop.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("cookie"));
                if let (false, Some(cookie)) = (has_cookie, jar.request_header(&current)) {
                    hop.headers.push(("Cookie".into(), cookie));
                }
            }

            let hop_url = current.clone();
            let head_chain = chain.clone();
            let chunk_chain = chain.clone();
            let result = send_hop(
                self.client()?,
                hop,
                move |head: &ResponseHead| on_hop_head(&head_chain, &hop_url, head),
                move |chunk: &[u8]| {
                    let mut on_chunk = chunk_chain.on_chunk.lock().unwrap();
                    (*on_chunk)(chunk)
                },
            )
            .await;

            match result {
                Ok(head) => return Ok(head),
                Err(err) if err.code == ErrorCode::Aborted => {
                    let Some((status, location)) = chain.redirect.lock().unwrap().take() else {
                        return Err(err);
                    };
                    if redirects == MAX_REDIRECTS {
                        return Err(Error {
                            code: ErrorCode::TransportError,
                            message: format!("stopped after {MAX_REDIRECTS} redirects"),
                        });
                    }
                    redirects += 1;
                    let next = current.join(&location).map_err(|err| Error {
                        code: ErrorCode::InvalidUrl,
                        message: format!("invalid redirect target {location:?}: {err}"),
                    })?;
                    if !matches!(next.scheme(), "http" | "https") {
                        return Err(Error {
                            code: ErrorCode::InvalidUrl,
                            message: format!("redirect to an unsupported scheme: {}", next.scheme()),
                        });
                    }
                    apply_redirect_status(status, &mut request);
                    previous = Some(std::mem::replace(&mut current, next));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

/// The head callback for every hop: absorbs the hop's cookies, then either
/// records a redirect to follow (and aborts the hop) or hands the final
/// response to the caller's `on_head`.
fn on_hop_head(chain: &Chain, url: &url::Url, head: &ResponseHead) -> ControlFlow<()> {
    if let Some(jar) = chain.jar {
        absorb_set_cookie(jar, url, &head.headers);
    }
    if let Some(location) = redirect_location(head) {
        *chain.redirect.lock().unwrap() = Some((head.status, location.to_owned()));
        return ControlFlow::Break(());
    }
    match chain.on_head.lock().unwrap().take() {
        Some(on_head) => on_head(head),
        None => ControlFlow::Continue(()),
    }
}

/// The Location of a response that redirects. Only 301, 302, 303, 307 and 308
/// are followed, as reqwest does; 300 and 304 come back as they are.
fn redirect_location(head: &ResponseHead) -> Option<&str> {
    if !matches!(head.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    head.header_values("location").next()
}

/// Changes `request`'s method and body for a redirect with `status`, the way
/// reqwest does: 301 and 302 turn a POST into a GET, 303 turns anything but a
/// HEAD into a GET, and 307 and 308 keep both. Turning a request into a GET
/// drops its body and the headers describing it.
fn apply_redirect_status(status: u16, request: &mut Request) {
    match status {
        301 | 302 if request.method == Method::Post => {
            request.method = Method::Get;
            drop_payload(request);
        }
        303 => {
            if request.method != Method::Head {
                request.method = Method::Get;
            }
            drop_payload(request);
        }
        _ => {}
    }
}

fn drop_payload(request: &mut Request) {
    request.body.clear();
    request
        .headers
        .retain(|(name, _)| !PAYLOAD_HEADERS.iter().any(|header| name.eq_ignore_ascii_case(header)));
}

/// Drops the credential headers when a redirect leaves the origin of the
/// previous hop (scheme, host or port changes).
fn remove_sensitive_headers(headers: &mut Vec<(String, String)>, next: &url::Url, previous: &url::Url) {
    let cross_origin = next.scheme() != previous.scheme()
        || next.host_str() != previous.host_str()
        || next.port_or_known_default() != previous.port_or_known_default();
    if cross_origin {
        headers.retain(|(name, _)| !SENSITIVE_HEADERS.iter().any(|header| name.eq_ignore_ascii_case(header)));
    }
}

/// Sets `Referer` to the previous hop's URL, without its credentials or
/// fragment -- unless that would send an https URL to plain http, which
/// reqwest never does.
fn set_referer(headers: &mut Vec<(String, String)>, next: &url::Url, previous: &url::Url) {
    if next.scheme() == "http" && previous.scheme() == "https" {
        return;
    }
    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("referer"));
    headers.push(("Referer".into(), referer.to_string()));
}

/// One hop: the c-share request for `request`, streamed through the two
/// callbacks.
async fn send_hop(
    client: Arc<ffi::Client>,
    request: Request,
    on_head: impl FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
    on_chunk: impl FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
) -> Result<ResponseHead, Error> {
    let (handle, receiver) = client.send_streaming(request, on_head, on_chunk)?;
    let mut cancel = CancelOnDrop {
        client,
        handle,
        done: false,
    };
    let result = receiver.await;
    cancel.done = true;
    result.unwrap_or_else(|_| {
        Err(Error {
            code: ErrorCode::TransportError,
            message: "the completion callback was dropped without running".into(),
        })
    })
}

/// The `http(s)://` URL whose cookies a WebSocket at `url` gets: the cookie
/// jar knows no `ws(s)://` scheme, and a browser treats them alike.
fn websocket_cookie_url(url: &url::Url) -> Result<url::Url, Error> {
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => {
            return Err(Error {
                code: ErrorCode::InvalidUrl,
                message: format!("not a WebSocket URL: {other}://"),
            });
        }
    };
    parse_url(&format!("{scheme}{}", &url.as_str()[url.scheme().len()..]))
}

/// Aborts a WebSocket handshake that is dropped before it is `done`.
struct CloseOnDrop {
    client: Arc<ffi::Client>,
    handle: u64,
    done: bool,
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if !self.done {
            self.client.ws_close(self.handle, WS_GOING_AWAY, "");
        }
    }
}

fn parse_url(url: &str) -> Result<url::Url, Error> {
    url::Url::parse(url).map_err(|err| Error {
        code: ErrorCode::InvalidUrl,
        message: format!("invalid URL: {err}"),
    })
}

fn absorb_set_cookie(jar: &PersistentJar, url: &url::Url, headers: &[(String, String)]) {
    let set_cookie_values: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())
        .collect();
    if set_cookie_values.is_empty() {
        return;
    }
    jar.set_cookies(set_cookie_values, url);
    jar.save();
}

/// Cancels the request if the send future is dropped before it completes. It
/// holds its client alive, so the event loop outlives every request in flight.
struct CancelOnDrop {
    client: Arc<ffi::Client>,
    handle: u64,
    done: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.done {
            self.client.cancel(self.handle);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;

    /// Serves `response` verbatim to every connection, and returns the
    /// address it listens on. Each request it read is sent to the returned
    /// receiver.
    fn serve(response: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        serve_with(move |_| response.as_bytes().to_vec())
    }

    /// Like [`serve`], but answers each request with `handler`'s bytes, given
    /// the request text.
    fn serve_with(
        handler: impl Fn(&str) -> Vec<u8> + Send + 'static,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream: TcpStream = stream.unwrap();
                let mut buf = [0u8; 4096];
                let read = stream.read(&mut buf).unwrap();
                let seen = String::from_utf8_lossy(&buf[..read]).into_owned();
                let _ = sender.send(seen.clone());
                stream.write_all(&handler(&seen)).unwrap();
            }
        });
        (format!("http://{addr}"), receiver)
    }

    /// The value of header `name` in a request as [`serve_with`] received it,
    /// matched case-insensitively.
    fn header_value(seen: &str, name: &str) -> Option<String> {
        seen.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
        })
    }

    /// `hello`, gzipped (`gzip -n`).
    const GZIP_HELLO: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 72, 205, 201, 201, 7, 0, 134, 166, 16, 54, 5, 0, 0, 0,
    ];

    #[tokio::test]
    async fn gets_a_response_with_status_headers_and_body() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nX-Twice: a\r\nX-Twice: b\r\nConnection: close\r\n\r\nhello",
        );

        let response = client.send(Request::get(format!("{url}/x")).header("X-Mine", "1"))
            .await
            .unwrap();

        // An HTTP error status is still a successful exchange.
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header_values("x-twice").collect::<Vec<_>>(), ["a", "b"]);
        let seen = requests.recv().unwrap();
        assert!(seen.starts_with("GET /x HTTP/1.1"), "{seen}");
        assert!(seen.contains("X-Mine: 1"), "{seen}");
    }

    #[tokio::test]
    async fn posts_a_body() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");

        let response = client.send(Request::post(url, "payload")).await.unwrap();

        assert_eq!(response.status, 204);
        let seen = requests.recv().unwrap();
        assert!(seen.starts_with("POST / HTTP/1.1"), "{seen}");
        assert!(seen.ends_with("payload"), "{seen}");
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_transport_error() {
        let client = HttpClient::start().unwrap();
        // Bind then drop, so the port is very likely closed.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();

        let err = client.send(Request::get(format!("http://{addr}/"))).await.unwrap_err();

        assert_eq!(err.code, ErrorCode::CouldNotConnect, "{err}");
    }

    #[tokio::test]
    async fn a_malformed_url_is_a_transport_error() {
        let client = HttpClient::start().unwrap();
        let err = client.send(Request::get("http://")).await.unwrap_err();

        assert!(
            matches!(err.code, ErrorCode::InvalidUrl | ErrorCode::CouldNotResolveHost),
            "{err}"
        );
    }

    #[tokio::test]
    async fn streams_the_body_and_returns_the_head_on_completion() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
        );

        let chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let collected = chunks.clone();
        let head = client.send_streaming(
            Request::get(url),
            |_head| std::ops::ControlFlow::Continue(()),
            move |chunk| {
                collected.lock().unwrap().extend_from_slice(chunk);
                std::ops::ControlFlow::Continue(())
            },
        )
        .await
        .unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(*chunks.lock().unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn on_head_sees_the_status_and_headers_before_any_body() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Early: yes\r\nConnection: close\r\n\r\nhello world",
        );

        let chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let seen_head = std::sync::Arc::new(std::sync::Mutex::new(None::<(u16, Vec<String>, usize)>));
        let (collected, recorded) = (chunks.clone(), seen_head.clone());
        client.send_streaming(
            Request::get(url),
            move |head| {
                let values = head.header_values("x-early").map(str::to_owned).collect();
                // Nothing of the body may have arrived yet.
                *recorded.lock().unwrap() = Some((head.status, values, collected.lock().unwrap().len()));
                std::ops::ControlFlow::Continue(())
            },
            {
                let collected = chunks.clone();
                move |chunk| {
                    collected.lock().unwrap().extend_from_slice(chunk);
                    std::ops::ControlFlow::Continue(())
                }
            },
        )
        .await
        .unwrap();

        let (status, values, body_bytes_before) = seen_head.lock().unwrap().take().unwrap();
        assert_eq!(status, 200);
        assert_eq!(values, ["yes"]);
        assert_eq!(body_bytes_before, 0);
    }

    #[tokio::test]
    async fn breaking_from_on_head_aborts_before_the_body() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found",
        );

        let chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let collected = chunks.clone();
        let err = client.send_streaming(
            Request::get(url),
            |head| {
                if head.status == 404 {
                    std::ops::ControlFlow::Break(())
                } else {
                    std::ops::ControlFlow::Continue(())
                }
            },
            move |chunk| {
                collected.lock().unwrap().extend_from_slice(chunk);
                std::ops::ControlFlow::Continue(())
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::Aborted, "{err}");
        assert!(chunks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn aborting_from_on_chunk_reports_aborted() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
        );

        let err = client.send_streaming(
            Request::get(url),
            |_head| std::ops::ControlFlow::Continue(()),
            |_chunk| std::ops::ControlFlow::Break(()),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::Aborted, "{err}");
    }

    #[tokio::test]
    async fn send_with_cookies_attaches_the_jars_header() {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, requests) = serve("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        jar.add("session=abc", &url::Url::parse(&url).unwrap()).unwrap();

        client.send_with_cookies(jar, Request::get(&url)).await.unwrap();

        let seen = requests.recv().unwrap();
        assert!(seen.contains("Cookie: session=abc"), "{seen}");
    }

    #[tokio::test]
    async fn send_with_cookies_absorbs_set_cookie_into_the_jar() {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, _requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: session=xyz\r\nConnection: close\r\n\r\n",
        );
        let parsed_url = url::Url::parse(&url).unwrap();

        client.send_with_cookies(jar, Request::get(&url)).await.unwrap();

        let header = jar.request_header(&parsed_url).unwrap();
        assert!(header.contains("session=xyz"), "{header}");
    }

    #[tokio::test]
    async fn send_streaming_with_cookies_does_both() {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: session=xyz\r\nConnection: close\r\n\r\nhello",
        );
        let parsed_url = url::Url::parse(&url).unwrap();
        jar.add("before=1", &parsed_url).unwrap();

        let chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let collected = chunks.clone();
        let head = client.send_streaming_with_cookies(
            jar,
            Request::get(&url),
            |_head| std::ops::ControlFlow::Continue(()),
            move |chunk| {
                collected.lock().unwrap().extend_from_slice(chunk);
                std::ops::ControlFlow::Continue(())
            },
        )
        .await
        .unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(*chunks.lock().unwrap(), b"hello");
        let seen = requests.recv().unwrap();
        assert!(seen.contains("Cookie: before=1"), "{seen}");
        let header = jar.request_header(&parsed_url).unwrap();
        assert!(header.contains("session=xyz"), "{header}");
    }

    #[tokio::test]
    async fn set_cookie_is_in_the_jar_before_on_head_returns() {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, _requests) = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: early=1\r\nConnection: close\r\n\r\nhello",
        );
        let parsed_url = url::Url::parse(&url).unwrap();

        // Abort right at the head: the cookie must still have been absorbed,
        // and the body must never have been read.
        let err = client.send_streaming_with_cookies(
            jar,
            Request::get(&url),
            |_head| std::ops::ControlFlow::Break(()),
            |_chunk| std::ops::ControlFlow::Continue(()),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::Aborted, "{err}");
        let header = jar.request_header(&parsed_url).unwrap();
        assert!(header.contains("early=1"), "{header}");
    }

    #[tokio::test]
    async fn sends_the_headers_reqwest_sends_by_default() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");

        client.send(Request::get(url)).await.unwrap();

        let seen = requests.recv().unwrap();
        assert_eq!(header_value(&seen, "accept").as_deref(), Some("*/*"), "{seen}");
        assert!(
            header_value(&seen, "accept-encoding").unwrap().starts_with("gzip,deflate"),
            "{seen}"
        );
        assert_eq!(header_value(&seen, "user-agent"), None, "{seen}");
        assert_eq!(header_value(&seen, "expect"), None, "{seen}");
    }

    #[tokio::test]
    async fn a_callers_own_accept_and_user_agent_are_kept() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");

        client.send(Request::get(url).header("User-Agent", "test/1").header("Accept", "text/html"))
            .await
            .unwrap();

        let seen = requests.recv().unwrap();
        assert_eq!(header_value(&seen, "user-agent").as_deref(), Some("test/1"), "{seen}");
        assert_eq!(header_value(&seen, "accept").as_deref(), Some("text/html"), "{seen}");
    }

    #[tokio::test]
    async fn a_decoded_body_drops_the_headers_describing_the_encoded_one() {
        let client = HttpClient::start().unwrap();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            GZIP_HELLO.len()
        )
        .into_bytes();
        response.extend_from_slice(GZIP_HELLO);
        let (url, _requests) = serve_with(move |_| response.clone());

        let response = client.send(Request::get(url)).await.unwrap();

        assert_eq!(response.body, b"hello");
        assert_eq!(response.header_values("content-encoding").count(), 0);
        assert_eq!(response.header_values("content-length").count(), 0);
    }

    #[tokio::test]
    async fn a_302_turns_a_post_into_a_get_without_its_body() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve_with(|request| {
            if request.starts_with("POST /a ") {
                "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_bytes().to_vec()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone".as_bytes().to_vec()
            }
        });

        let response = client.send(Request::post(format!("{url}/a"), "payload")).await.unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"done");
        assert!(requests.recv().unwrap().starts_with("POST /a "));
        let second = requests.recv().unwrap();
        assert!(second.starts_with("GET /b HTTP/1.1"), "{second}");
        assert!(!second.contains("payload"), "{second}");
    }

    #[tokio::test]
    async fn a_307_keeps_the_method_and_the_body() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve_with(|request| {
            if request.starts_with("POST /a ") {
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_bytes().to_vec()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone".as_bytes().to_vec()
            }
        });

        let response = client.send(Request::post(format!("{url}/a"), "payload")).await.unwrap();

        assert_eq!(response.status, 200);
        requests.recv().unwrap();
        let second = requests.recv().unwrap();
        assert!(second.starts_with("POST /b "), "{second}");
        assert!(second.ends_with("payload"), "{second}");
    }

    #[tokio::test]
    async fn a_redirect_to_another_origin_drops_credentials_and_sets_a_referer() {
        let client = HttpClient::start().unwrap();
        let (target, target_requests) =
            serve("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let location = format!("{target}/landing");
        let (start, _start_requests) = serve_with(move |_| {
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_bytes()
        });
        let start_url = format!("{start}/start");

        client.send(Request::get(&start_url).header("Cookie", "session=1").header("Authorization", "Basic eA=="))
            .await
            .unwrap();

        let seen = target_requests.recv().unwrap();
        assert_eq!(header_value(&seen, "cookie"), None, "{seen}");
        assert_eq!(header_value(&seen, "authorization"), None, "{seen}");
        assert_eq!(header_value(&seen, "referer").as_deref(), Some(start_url.as_str()), "{seen}");
    }

    #[tokio::test]
    async fn a_redirects_set_cookie_is_sent_to_the_next_hop() {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, requests) = serve_with(|request| {
            if request.starts_with("GET /a ") {
                "HTTP/1.1 302 Found\r\nSet-Cookie: hop=1\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_bytes()
                    .to_vec()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_bytes().to_vec()
            }
        });

        client.send_with_cookies(jar, Request::get(format!("{url}/a"))).await.unwrap();

        requests.recv().unwrap();
        let second = requests.recv().unwrap();
        assert!(header_value(&second, "cookie").unwrap_or_default().contains("hop=1"), "{second}");
    }

    #[tokio::test]
    async fn a_redirect_loop_stops_after_ten_redirects() {
        let client = HttpClient::start().unwrap();
        let (url, requests) = serve_with(|_| {
            "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_bytes().to_vec()
        });

        let err = client.send(Request::get(url)).await.unwrap_err();

        assert_eq!(err.code, ErrorCode::TransportError, "{err}");
        assert!(err.message.contains("10 redirects"), "{err}");
        // The original request plus the ten it followed.
        assert_eq!(requests.try_iter().count(), 11);
    }

    #[tokio::test]
    async fn streaming_reports_only_the_final_hop_to_its_callbacks() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve_with(|request| {
            if request.starts_with("GET /a ") {
                "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_bytes().to_vec()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".as_bytes().to_vec()
            }
        });
        let statuses = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u16>::new()));
        let chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let (seen_statuses, collected) = (statuses.clone(), chunks.clone());

        let head = client.send_streaming(
            Request::get(format!("{url}/a")),
            move |head| {
                seen_statuses.lock().unwrap().push(head.status);
                std::ops::ControlFlow::Continue(())
            },
            move |chunk| {
                collected.lock().unwrap().extend_from_slice(chunk);
                std::ops::ControlFlow::Continue(())
            },
        )
        .await
        .unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(*statuses.lock().unwrap(), [200]);
        assert_eq!(*chunks.lock().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn sends_after_a_shutdown_fail_to_submit() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        client.shutdown();

        let err = client.send(Request::get(url)).await.unwrap_err();

        assert_eq!(err.code, ErrorCode::SubmitFailed, "{err}");
    }

    #[tokio::test]
    async fn a_request_in_flight_survives_a_shutdown() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve_with(|_| {
            thread::sleep(Duration::from_millis(200));
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone".as_bytes().to_vec()
        });
        let pending = tokio::spawn({
            let client = client.clone();
            async move { client.send(Request::get(url)).await }
        });
        // Let the request reach c-share before the handle is shut down.
        tokio::time::sleep(Duration::from_millis(50)).await;

        client.shutdown();

        let response = pending.await.unwrap().unwrap();
        assert_eq!(response.body, b"done");
    }

    #[test]
    fn dropping_the_last_handle_stops_and_joins_the_loop() {
        // Start and drop without sending: a stop that lands before the loop
        // has begun must still let the thread finish, or this never returns.
        for _ in 0..50 {
            drop(HttpClient::start().unwrap());
        }
    }

    /// SHA-1 of `data`, for a WebSocket's `Sec-WebSocket-Accept`.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        let mut message = data.to_vec();
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
        for chunk in message.chunks(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = h;
            for (i, word) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5A827999),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
                (e, d, c, b, a) = (d, c, b.rotate_left(30), a, t);
            }
            for (state, value) in h.iter_mut().zip([a, b, c, d, e]) {
                *state = state.wrapping_add(value);
            }
        }
        let mut out = [0u8; 20];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Reads one (masked) frame from a WebSocket client: whether RSV1 (the
    /// compressed bit) is set, the opcode and the payload.
    fn read_frame(stream: &mut TcpStream) -> (bool, u8, Vec<u8>) {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).unwrap();
        let mut len = u64::from(head[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).unwrap();
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).unwrap();
            len = u64::from_be_bytes(ext);
        }
        assert!(head[1] & 0x80 != 0, "a client frame must be masked");
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).unwrap();
        let mut payload = vec![0u8; usize::try_from(len).unwrap()];
        stream.read_exact(&mut payload).unwrap();
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        (head[0] & 0x40 != 0, head[0] & 0x0f, payload)
    }

    /// An unmasked (server) frame, with RSV1 set if `compressed`.
    fn frame(compressed: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let first = 0x80 | if compressed { 0x40 } else { 0 } | opcode;
        let mut out = vec![first];
        match u16::try_from(payload.len()) {
            Ok(len @ 0..=125) => out.push(u8::try_from(len).unwrap()),
            Ok(len) => {
                out.push(126);
                out.extend_from_slice(&len.to_be_bytes());
            }
            Err(_) => {
                out.push(127);
                out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    /// The permessage-deflate state of one side of [`serve_websocket`].
    struct Deflate {
        compress: flate2::Compress,
        decompress: flate2::Decompress,
    }

    impl Deflate {
        fn new() -> Self {
            // Raw deflate: permessage-deflate carries no zlib header.
            Self {
                compress: flate2::Compress::new(flate2::Compression::default(), false),
                decompress: flate2::Decompress::new(false),
            }
        }

        /// `data` compressed for the wire: a sync flush, without its
        /// `00 00 ff ff` tail.
        fn compress(&mut self, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(data.len() + 64);
            self.compress.compress_vec(data, &mut out, flate2::FlushCompress::Sync).unwrap();
            out.truncate(out.len() - 4);
            out
        }

        fn decompress(&mut self, data: &[u8]) -> Vec<u8> {
            let mut input = data.to_vec();
            input.extend_from_slice(&[0, 0, 0xff, 0xff]);
            let mut out = Vec::new();
            let start = self.decompress.total_in();
            // `decompress_vec` only fills spare capacity: grow until all the
            // input is in and the output stopped short of filling it.
            loop {
                out.reserve(64 * 1024);
                let consumed = usize::try_from(self.decompress.total_in() - start).unwrap();
                self.decompress
                    .decompress_vec(&input[consumed..], &mut out, flate2::FlushDecompress::Sync)
                    .unwrap();
                let all_in = self.decompress.total_in() - start == input.len() as u64;
                if all_in && out.len() < out.capacity() {
                    return out;
                }
            }
        }
    }

    /// A WebSocket server that accepts the upgrade (with a `Set-Cookie`, and
    /// permessage-deflate if offered), greets with a text message, then
    /// echoes every data frame and the close frame. The upgrade request it
    /// read goes to the receiver, then a `frame compressed=<bool>` line for
    /// each data frame it gets.
    pub(crate) fn serve_websocket() -> (String, std::sync::mpsc::Receiver<String>) {
        use base64::Engine;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            let key = header_value(&request, "sec-websocket-key").unwrap();
            let mut deflate = header_value(&request, "sec-websocket-extensions")
                .is_some_and(|offer| offer.contains("permessage-deflate"))
                .then(Deflate::new);
            let _ = sender.send(request);
            let accept = base64::engine::general_purpose::STANDARD
                .encode(sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
            let extension = if deflate.is_some() { "Sec-WebSocket-Extensions: permessage-deflate\r\n" } else { "" };
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\nSet-Cookie: ws_session=1\r\n{extension}\r\n"
            )
            .into_bytes();
            let message = |opcode: u8, payload: &[u8], deflate: &mut Option<Deflate>| match deflate {
                Some(deflate) => frame(true, opcode, &deflate.compress(payload)),
                None => frame(false, opcode, payload),
            };
            response.extend(message(1, b"welcome", &mut deflate));
            stream.write_all(&response).unwrap();
            loop {
                let (compressed, opcode, payload) = read_frame(&mut stream);
                if opcode == 8 {
                    stream.write_all(&frame(false, 8, &payload)).unwrap();
                    break;
                }
                let _ = sender.send(format!("frame compressed={compressed}"));
                let payload = match (&mut deflate, compressed) {
                    (Some(deflate), true) => deflate.decompress(&payload),
                    _ => payload,
                };
                stream.write_all(&message(opcode, &payload, &mut deflate)).unwrap();
            }
        });
        (format!("ws://{addr}"), receiver)
    }

    #[test]
    fn sha1_matches_the_rfc_6455_example() {
        use base64::Engine;
        let accept = sha1(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(base64::engine::general_purpose::STANDARD.encode(accept), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// Opens a WebSocket to [`serve_websocket`] with `options`, checks the
    /// upgrade, the cookies and a round trip of messages, then closes it.
    /// Returns the `frame compressed=` lines the server saw.
    async fn websocket_round_trip(options: WsOptions) -> Vec<String> {
        let client = HttpClient::start().unwrap();
        let jar: &'static PersistentJar = Box::leak(Box::new(PersistentJar::load(None)));
        let (url, seen) = serve_websocket();
        let http_url = url::Url::parse(&url.replacen("ws://", "http://", 1)).unwrap();
        jar.add("session=abc", &http_url).unwrap();

        let request = Request::get(format!("{url}/chat"))
            .header("Origin", "https://example.com")
            .header("Sec-WebSocket-Extensions", "x-unsupported");
        let (socket, head, mut events) = client.connect_websocket(Some(jar), request, options).await.unwrap();

        assert_eq!(head.status, 101);
        let upgrade = seen.recv().unwrap();
        assert!(upgrade.starts_with("GET /chat HTTP/1.1"), "{upgrade}");
        assert_eq!(header_value(&upgrade, "origin").as_deref(), Some("https://example.com"));
        assert_eq!(header_value(&upgrade, "cookie").as_deref(), Some("session=abc"));
        // The caller's own extension is never sent; ours only when asked.
        let offered = header_value(&upgrade, "sec-websocket-extensions");
        assert_eq!(offered.as_deref(), options.deflate.then_some("permessage-deflate"));
        assert!(jar.request_header(&http_url).unwrap().contains("ws_session=1"));

        let big = "abcdefgh".repeat(10_000);
        socket.send(&WsMessage::Text("hi".into())).unwrap();
        socket.send(&WsMessage::Binary(vec![1, 2, 3])).unwrap();
        socket.send(&WsMessage::Text(big.clone())).unwrap();
        let mut messages = Vec::new();
        while messages.len() < 4 {
            match events.recv().await.unwrap() {
                WsEvent::Message(message) => messages.push(message),
                WsEvent::Closed(close) => panic!("closed early: {close:?}"),
            }
        }
        assert_eq!(
            messages,
            [
                WsMessage::Text("welcome".into()),
                WsMessage::Text("hi".into()),
                WsMessage::Binary(vec![1, 2, 3]),
                WsMessage::Text(big),
            ]
        );

        socket.close(1000, "bye");
        let WsEvent::Closed(close) = events.recv().await.unwrap() else {
            panic!("expected the close");
        };
        assert_eq!((close.code, close.reason.as_str()), (1000, "bye"));
        assert!(close.error.is_none(), "{close:?}");
        assert!(events.recv().await.is_none());
        assert!(socket.send(&WsMessage::Text("late".into())).is_err());
        seen.try_iter().collect()
    }

    #[tokio::test]
    async fn a_websocket_round_trip_with_cookies() {
        let frames = websocket_round_trip(WsOptions::default()).await;
        assert_eq!(frames, ["frame compressed=false"; 3]);
    }

    #[tokio::test]
    async fn a_websocket_round_trip_with_permessage_deflate() {
        let frames = websocket_round_trip(WsOptions { deflate: true }).await;
        assert_eq!(frames, ["frame compressed=true"; 3]);
    }

    #[tokio::test]
    async fn a_refused_websocket_upgrade_fails_with_its_status() {
        let client = HttpClient::start().unwrap();
        let (url, _requests) = serve("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        let err = client
            .connect_websocket(None, Request::get(url.replacen("http://", "ws://", 1)), WsOptions::default())
            .await
            .unwrap_err();

        assert!(err.message.contains("403"), "{err}");
    }

    #[tokio::test]
    async fn connect_websocket_rejects_a_non_websocket_url() {
        let client = HttpClient::start().unwrap();
        let err = client
            .connect_websocket(None, Request::get("https://example.com/"), WsOptions::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidUrl);
    }
}
