//! The unsafe half of [`super`]: c-share's `client_c.h` C API (see
//! `build.rs`), and the callback-to-`oneshot` bridge that turns its
//! completion callback into something `send` can `.await`. Only this module
//! sees raw pointers.

use std::ffi::{c_char, c_long, c_void};
use std::ops::ControlFlow;
use std::{ptr, slice};

use tokio::sync::{mpsc, oneshot};

use super::{Error, ErrorCode, Method, Request, ResponseHead, WsClose, WsEvent, WsMessage, WsOptions};

mod raw {
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
    include!(concat!(env!("OUT_DIR"), "/http_bindings.rs"));
}

type StreamCompletion = Result<ResponseHead, Error>;

/// Builds the C request `send`/`send_streaming` hand to c-share, plus the
/// owned header array it points into. The caller must keep both alive
/// until the `c_share_http_client_send` call returns (c-share copies
/// everything it needs out of the request before then), and must also keep
/// `request` itself alive that long, since the returned struct borrows its
/// url/body/header strings directly.
fn build_raw_request(request: &Request) -> (Vec<raw::c_share_http_header_t>, raw::c_share_http_request_t) {
    let headers: Vec<raw::c_share_http_header_t> = request
        .headers
        .iter()
        .map(|(name, value)| raw::c_share_http_header_t {
            name: name.as_ptr().cast::<c_char>(),
            name_len: name.len(),
            value: value.as_ptr().cast::<c_char>(),
            value_len: value.len(),
        })
        .collect();
    let pinned = request.pinned_public_key.as_deref();
    let raw_request = raw::c_share_http_request_t {
        url: request.url.as_ptr().cast::<c_char>(),
        url_len: request.url.len(),
        method: method_to_raw(request.method),
        headers: if headers.is_empty() {
            ptr::null()
        } else {
            headers.as_ptr()
        },
        headers_len: headers.len(),
        body: request.body.as_ptr(),
        body_len: request.body.len(),
        timeout_ms: i64::try_from(request.timeout.as_millis()).unwrap_or(i64::MAX),
        pinned_public_key: pinned.map_or(ptr::null(), |key| key.as_ptr().cast::<c_char>()),
        pinned_public_key_len: pinned.map_or(0, str::len),
        // Redirects are followed by `super`, not libcurl: each hop needs its
        // own cookies and headers, which libcurl would not recompute.
        follow_redirects: 0,
    };
    (headers, raw_request)
}

/// An owned `c_share_http_client_t*`. c-share starts the client's event loop
/// thread in `create`; dropping this stops that thread, waits for it, and frees
/// the client (`destroy`). Nothing here runs on Rust's side of the thread.
pub(super) struct Client {
    ptr: *mut raw::c_share_http_client,
}

// c-share documents `send` and `cancel` as safe from any thread, and `destroy`
// is only ever called from `Drop`, once, after every user has let go of it.
unsafe impl Send for Client {}
unsafe impl Sync for Client {}

impl Client {
    /// Starts a client. `None` if c-share could not create it.
    pub(super) fn start() -> Option<Client> {
        let ptr = unsafe { raw::c_share_http_client_create() };
        (!ptr.is_null()).then_some(Client { ptr })
    }

    /// Streams the response body through
    /// `on_chunk` instead of buffering it, and hands the status/headers to
    /// `on_head` as soon as they arrive -- see [`super::send_streaming`] for
    /// the full contract.
    pub(super) fn send_streaming<H, F>(
        &self,
        request: Request,
        on_head: H,
        on_chunk: F,
    ) -> Result<(u64, oneshot::Receiver<StreamCompletion>), Error>
    where
        H: FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
        F: FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel::<StreamCompletion>();
        let state = Box::new(StreamState {
            on_head: Some(on_head),
            on_chunk,
            completion: sender,
        });
        let context = Box::into_raw(state).cast::<c_void>();

        let (_headers, raw_request) = build_raw_request(&request);
        let handle = unsafe {
            raw::c_share_http_client_send(
                self.ptr,
                &raw_request,
                context,
                Some(body_trampoline::<H, F>),
                Some(completed_streaming::<H, F>),
                Some(head_trampoline::<H, F>),
            )
        };
        if handle == 0 {
            // Never submitted, so no trampoline will run: `context` is
            // still ours to free.
            drop(unsafe { Box::from_raw(context.cast::<StreamState<H, F>>()) });
            return Err(Error {
                code: ErrorCode::SubmitFailed,
                message: "c-share could not submit the request".into(),
            });
        }
        Ok((handle, receiver))
    }

    /// Cancels the request `handle`; its completion then reports
    /// [`ErrorCode::Aborted`]. A no-op if it already finished.
    pub(super) fn cancel(&self, handle: u64) {
        unsafe { raw::c_share_http_client_cancel(self.ptr, handle) };
    }

    /// Starts a WebSocket handshake for `request`. The receiver resolves
    /// with the 101 response once it is accepted, or the error if it is not;
    /// after that, the connection's messages and its close come through the
    /// event receiver.
    pub(super) fn open_websocket(
        &self,
        request: &Request,
        options: WsOptions,
    ) -> Result<(u64, oneshot::Receiver<WsOpened>, mpsc::UnboundedReceiver<WsEvent>), Error> {
        let (opened, opened_receiver) = oneshot::channel();
        let (events, events_receiver) = mpsc::unbounded_channel();
        let state = Box::new(WsState {
            opened: Some(opened),
            events,
        });
        let context = Box::into_raw(state).cast::<c_void>();

        let (_headers, raw_request) = build_raw_request(request);
        let raw_options = raw::c_share_http_ws_options_t {
            deflate: i32::from(options.deflate),
        };
        let handle = unsafe {
            raw::c_share_http_client_ws_open(
                self.ptr,
                &raw_request,
                &raw_options,
                context,
                Some(ws_opened),
                Some(ws_message),
                Some(ws_closed),
            )
        };
        if handle == 0 {
            // Never submitted, so `ws_closed` will not run: ours to free.
            drop(unsafe { Box::from_raw(context.cast::<WsState>()) });
            return Err(Error {
                code: ErrorCode::SubmitFailed,
                message: "c-share could not submit the WebSocket handshake".into(),
            });
        }
        Ok((handle, opened_receiver, events_receiver))
    }

    /// Queues `message` on the WebSocket `handle`. False if it is closed or
    /// closing.
    pub(super) fn ws_send(&self, handle: u64, message: &WsMessage) -> bool {
        let (kind, data) = match message {
            WsMessage::Text(text) => (raw::c_share_http_ws_type_t::C_SHARE_HTTP_WS_TEXT, text.as_bytes()),
            WsMessage::Binary(bytes) => (raw::c_share_http_ws_type_t::C_SHARE_HTTP_WS_BINARY, bytes.as_slice()),
        };
        unsafe { raw::c_share_http_client_ws_send(self.ptr, handle, kind, data.as_ptr(), data.len()) == 0 }
    }

    /// Closes the WebSocket `handle` (or aborts its handshake). A no-op if it
    /// is already closed or closing.
    pub(super) fn ws_close(&self, handle: u64, code: u16, reason: &str) {
        unsafe {
            raw::c_share_http_client_ws_close(
                self.ptr,
                handle,
                code,
                reason.as_ptr().cast::<c_char>(),
                reason.len(),
            )
        };
    }
}

/// How a WebSocket handshake ended: the 101 response, or why it failed.
pub(super) type WsOpened = Result<ResponseHead, Error>;

/// What `context` points to for a WebSocket. `ws_closed` runs exactly once,
/// last, and is the one that reclaims it.
struct WsState {
    /// Taken by `ws_opened`, or by `ws_closed` if the handshake failed.
    opened: Option<oneshot::Sender<WsOpened>>,
    events: mpsc::UnboundedSender<WsEvent>,
}

unsafe extern "C" fn ws_opened(
    context: *mut c_void,
    status_code: c_long,
    headers: *const raw::c_share_http_header_t,
    headers_len: usize,
) {
    let state = unsafe { &mut *context.cast::<WsState>() };
    if let Some(opened) = state.opened.take() {
        let _ = opened.send(Ok(ResponseHead {
            status: u16::try_from(status_code).unwrap_or(0),
            headers: unsafe { headers_from_raw(headers, headers_len) },
        }));
    }
}

unsafe extern "C" fn ws_message(
    context: *mut c_void,
    kind: raw::c_share_http_ws_type_t,
    data: *const u8,
    size: usize,
) {
    let state = unsafe { &*context.cast::<WsState>() };
    let data = unsafe { bytes(data, size) };
    let message = match kind {
        raw::c_share_http_ws_type_t::C_SHARE_HTTP_WS_TEXT => WsMessage::Text(String::from_utf8_lossy(data).into_owned()),
        raw::c_share_http_ws_type_t::C_SHARE_HTTP_WS_BINARY => WsMessage::Binary(data.to_vec()),
    };
    // Nobody listens any more once the receiver is dropped; nothing to do.
    let _ = state.events.send(WsEvent::Message(message));
}

unsafe extern "C" fn ws_closed(
    context: *mut c_void,
    error: raw::c_share_http_error_t,
    code: u16,
    reason: *const c_char,
    reason_len: usize,
) {
    let mut state = unsafe { Box::from_raw(context.cast::<WsState>()) };
    let error = match error.code {
        raw::c_share_http_error_code_t::C_SHARE_HTTP_ERROR_NONE => None,
        raw_code => Some(Error {
            code: error_code_from_raw(raw_code),
            message: String::from_utf8_lossy(unsafe { bytes(error.message.cast::<u8>(), error.message_len) })
                .into_owned(),
        }),
    };
    if let Some(opened) = state.opened.take() {
        // The handshake never finished.
        let _ = opened.send(Err(error.unwrap_or_else(|| Error {
            code: ErrorCode::TransportError,
            message: "the WebSocket closed during its handshake".into(),
        })));
        return;
    }
    let reason = String::from_utf8_lossy(unsafe { bytes(reason.cast::<u8>(), reason_len) }).into_owned();
    let _ = state.events.send(WsEvent::Closed(WsClose { code, reason, error }));
}

impl Drop for Client {
    /// Stops the event loop, waits for its thread, and frees the client. Runs
    /// when the last `HttpClient` handle goes, so it must not happen on the
    /// loop thread: a callback holding the last handle would make the join
    /// wait for itself. Nothing in this crate hands a callback a handle.
    fn drop(&mut self) {
        unsafe { raw::c_share_http_client_destroy(self.ptr) };
    }
}

/// What `context` points to for a [`Client::send_streaming`] call: the
/// caller's head closure (taken on first use), the chunk closure, plus the
/// oneshot sender for the final status/headers. All three trampolines get the
/// same `context` pointer (that is c-share's contract), but only
/// `completed_streaming` ever reclaims (`Box::from_raw`s) it, since it is
/// guaranteed to run exactly once, after every other trampoline call for
/// that request.
struct StreamState<H, F> {
    on_head: Option<H>,
    on_chunk: F,
    completion: oneshot::Sender<StreamCompletion>,
}

/// c-share's head callback, monomorphized per closure types: runs once per
/// final response, as soon as its header block ends -- before any
/// `body_trampoline` call. Like the body callback, it runs synchronously on
/// the event-loop thread.
unsafe extern "C" fn head_trampoline<H, F>(
    context: *mut c_void,
    status_code: c_long,
    headers: *const raw::c_share_http_header_t,
    headers_len: usize,
) -> raw::c_share_http_action_t
where
    H: FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
    F: FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
{
    // Not reclaimed here -- completed_streaming<H, F> owns that.
    let state = unsafe { &mut *context.cast::<StreamState<H, F>>() };
    let Some(on_head) = state.on_head.take() else {
        return raw::c_share_http_action_t::C_SHARE_HTTP_ACTION_CONTINUE;
    };
    let head = ResponseHead {
        status: u16::try_from(status_code).unwrap_or(0),
        headers: unsafe { headers_from_raw(headers, headers_len) },
    };
    match on_head(&head) {
        ControlFlow::Continue(()) => raw::c_share_http_action_t::C_SHARE_HTTP_ACTION_CONTINUE,
        ControlFlow::Break(()) => raw::c_share_http_action_t::C_SHARE_HTTP_ACTION_ABORT,
    }
}

/// c-share's body callback, monomorphized per closure types: runs once per
/// chunk, synchronously on the event-loop thread, for as long as the
/// transfer is in flight. `data` is only valid for this call.
unsafe extern "C" fn body_trampoline<H, F>(
    context: *mut c_void,
    data: *const u8,
    size: usize,
) -> raw::c_share_http_action_t
where
    H: FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
    F: FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
{
    // Not reclaimed here -- completed_streaming<H, F> owns that, and is
    // guaranteed to run after every call to this function.
    let state = unsafe { &mut *context.cast::<StreamState<H, F>>() };
    let chunk = unsafe { bytes(data, size) };
    match (state.on_chunk)(chunk) {
        ControlFlow::Continue(()) => raw::c_share_http_action_t::C_SHARE_HTTP_ACTION_CONTINUE,
        ControlFlow::Break(()) => raw::c_share_http_action_t::C_SHARE_HTTP_ACTION_ABORT,
    }
}

/// c-share's completion callback for a streaming send, monomorphized per
/// closure types: runs exactly once, after every chunk has already gone
/// through `body_trampoline::<H, F>`. `response.body` is always empty here
/// (c-share leaves it empty whenever a body callback was supplied), so only
/// `status_code`/`headers` are read.
unsafe extern "C" fn completed_streaming<H, F>(
    context: *mut c_void,
    response: raw::c_share_http_response_t,
    error: raw::c_share_http_error_t,
) where
    H: FnOnce(&ResponseHead) -> ControlFlow<()> + Send + 'static,
    F: FnMut(&[u8]) -> ControlFlow<()> + Send + 'static,
{
    let state = unsafe { Box::from_raw(context.cast::<StreamState<H, F>>()) };
    let result = match error.code {
        raw::c_share_http_error_code_t::C_SHARE_HTTP_ERROR_NONE => Ok(ResponseHead {
            status: u16::try_from(response.status_code).unwrap_or(0),
            headers: unsafe { headers_from_raw(response.headers, response.headers_len) },
        }),
        code => Err(Error {
            code: error_code_from_raw(code),
            message: String::from_utf8_lossy(unsafe {
                bytes(error.message.cast::<u8>(), error.message_len)
            })
            .into_owned(),
        }),
    };
    // The receiver is gone if the `send_streaming` future was dropped;
    // nobody is waiting for the result then.
    let _ = state.completion.send(result);
}

/// `slice::from_raw_parts`, except that the pointer of an empty buffer may be
/// null (or dangling).
unsafe fn bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    }
}

unsafe fn headers_from_raw(
    headers: *const raw::c_share_http_header_t,
    len: usize,
) -> Vec<(String, String)> {
    if headers.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { slice::from_raw_parts(headers, len) }
        .iter()
        .map(|header| unsafe {
            (
                String::from_utf8_lossy(bytes(header.name.cast::<u8>(), header.name_len))
                    .into_owned(),
                String::from_utf8_lossy(bytes(header.value.cast::<u8>(), header.value_len))
                    .into_owned(),
            )
        })
        .collect()
}

fn method_to_raw(method: Method) -> raw::c_share_http_method_t {
    use raw::c_share_http_method_t as M;
    match method {
        Method::Get => M::C_SHARE_HTTP_METHOD_GET,
        Method::Post => M::C_SHARE_HTTP_METHOD_POST,
        Method::Put => M::C_SHARE_HTTP_METHOD_PUT,
        Method::Patch => M::C_SHARE_HTTP_METHOD_PATCH,
        Method::Delete => M::C_SHARE_HTTP_METHOD_DELETE,
        Method::Head => M::C_SHARE_HTTP_METHOD_HEAD,
        Method::Options => M::C_SHARE_HTTP_METHOD_OPTIONS,
    }
}

fn error_code_from_raw(code: raw::c_share_http_error_code_t) -> ErrorCode {
    use raw::c_share_http_error_code_t as E;
    match code {
        E::C_SHARE_HTTP_ERROR_INVALID_URL => ErrorCode::InvalidUrl,
        E::C_SHARE_HTTP_ERROR_COULD_NOT_RESOLVE_HOST => ErrorCode::CouldNotResolveHost,
        E::C_SHARE_HTTP_ERROR_COULD_NOT_CONNECT => ErrorCode::CouldNotConnect,
        E::C_SHARE_HTTP_ERROR_TLS_ERROR => ErrorCode::TlsError,
        E::C_SHARE_HTTP_ERROR_TIMEOUT => ErrorCode::Timeout,
        E::C_SHARE_HTTP_ERROR_ABORTED => ErrorCode::Aborted,
        E::C_SHARE_HTTP_ERROR_TRANSPORT_ERROR | E::C_SHARE_HTTP_ERROR_NONE => {
            ErrorCode::TransportError
        }
    }
}
