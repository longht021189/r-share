//! A sentry transport that sends envelopes through [`crate::http_client`]
//! (c-share's libcurl) instead of sentry's reqwest one.
//!
//! Sentry's own transport thread is only built with its `reqwest` feature, so
//! this module runs the same kind of thread itself: a bounded queue, one
//! worker thread, and a single-threaded runtime to drive [`HttpClient::send`].
//! The rate limits are sentry's [`RateLimiter`], which needs only its `httpdate`
//! feature.
//!
//! Proxies and `accept_invalid_certs` are not wired through yet: c-share's
//! http has no proxy or certificate-verification switch. Setting them logs a
//! debug message and sends without them.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

use sentry::client_report::{Reason as LossReason, Recorder};
use sentry::protocol::{EnvelopeItem, ItemContainer};
use sentry::transports::{RateLimiter, RateLimitingCategory};
use sentry::{Envelope, Transport, TransportFactory, TransportOptions, sentry_debug};

use crate::http_client::{HttpClient, Request};

/// How many envelopes may wait for the worker, as sentry's transport allows.
const QUEUE_LEN: usize = 30;

/// Hand this to `ClientOptions::transport`; sentry calls it once per client.
/// Sends go through `http`, so it must stay alive as long as sentry does.
pub struct HttpTransportFactory {
    http: HttpClient,
}

impl HttpTransportFactory {
    pub fn new(http: HttpClient) -> Self {
        Self { http }
    }
}

impl TransportFactory for HttpTransportFactory {
    fn create_transport_with_options(&self, options: TransportOptions) -> Arc<dyn Transport> {
        Arc::new(HttpTransport::new(options, self.http.clone()))
    }
}

/// What the worker is asked to do, in queue order.
enum Task {
    Send(Envelope),
    /// Answered once every envelope queued before it has been handled.
    Flush(SyncSender<()>),
}

struct HttpTransport {
    tasks: SyncSender<Task>,
    recorder: Recorder,
}

impl HttpTransport {
    fn new(options: TransportOptions, http: HttpClient) -> Self {
        let TransportOptions {
            dsn,
            user_agent,
            http_proxy,
            https_proxy,
            accept_invalid_certs,
            client_report_recorder,
            ..
        } = options;

        if http_proxy.is_some() || https_proxy.is_some() || accept_invalid_certs {
            sentry_debug!("proxy and accept_invalid_certs are not supported by the c-share transport; ignoring them");
        }

        let auth = dsn.to_auth(Some(&user_agent)).to_string();
        let url = dsn.envelope_api_url().to_string();
        let (tasks, queue) = mpsc::sync_channel(QUEUE_LEN);
        let worker = Worker {
            http,
            recorder: client_report_recorder.clone(),
            url,
            auth,
            limits: RateLimiter::new(),
        };
        thread::Builder::new()
            .name("sentry-transport".into())
            .spawn(move || worker.run(queue))
            .expect("failed to spawn the sentry transport thread");

        Self {
            tasks,
            recorder: client_report_recorder,
        }
    }
}

impl Transport for HttpTransport {
    fn send_envelope(&self, envelope: Envelope) {
        match self.tasks.try_send(Task::Send(envelope)) {
            Ok(()) => {}
            Err(TrySendError::Full(Task::Send(envelope))) => {
                self.recorder.record_lost_data(&envelope, LossReason::QueueOverflow);
            }
            Err(TrySendError::Disconnected(Task::Send(envelope))) => {
                self.recorder.record_lost_data(&envelope, LossReason::InternalError);
            }
            Err(_) => {}
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        let (ack, done) = mpsc::sync_channel(1);
        if self.tasks.send(Task::Flush(ack)).is_err() {
            return false;
        }
        done.recv_timeout(timeout).is_ok()
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        self.flush(timeout)
    }
}

/// Owns everything the worker thread needs: the queue's consumer side is
/// passed to [`Worker::run`] separately.
struct Worker {
    http: HttpClient,
    recorder: Recorder,
    url: String,
    auth: String,
    limits: RateLimiter,
}

impl Worker {
    fn run(mut self, queue: Receiver<Task>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build the sentry transport runtime");
        for task in queue {
            match task {
                Task::Flush(ack) => {
                    let _ = ack.send(());
                }
                Task::Send(envelope) => runtime.block_on(self.deliver(envelope)),
            }
        }
    }

    async fn deliver(&mut self, envelope: Envelope) {
        if all_rate_limited(&self.limits, &envelope) {
            self.recorder.record_lost_data(&envelope, LossReason::RatelimitBackoff);
            return;
        }

        let mut body = Vec::new();
        if envelope.to_writer(&mut body).is_err() {
            self.recorder.record_lost_data(&envelope, LossReason::InternalError);
            return;
        }
        let request = Request::post(self.url.clone(), body).header("X-Sentry-Auth", self.auth.clone());

        match self.http.send(request).await {
            Ok(response) => {
                if let Some(value) = response.header_values("x-sentry-rate-limits").next() {
                    self.limits.update_from_sentry_header(value);
                } else if let Some(value) = response.header_values("retry-after").next() {
                    self.limits.update_from_retry_after(value);
                } else if response.status == 429 {
                    self.limits.update_from_429();
                }

                if response.status == 413 {
                    sentry_debug!("Sentry rejected the envelope as too large (413)");
                }
                sentry_debug!("Get response: `{}`", String::from_utf8_lossy(&response.body));
                // A 429 is not recorded here: the server records that loss itself.
                if (400..=599).contains(&response.status) && response.status != 429 {
                    self.recorder.record_lost_data(&envelope, LossReason::SendError);
                }
            }
            Err(err) => {
                sentry_debug!("Failed to send envelope: {}", err);
                self.recorder.record_lost_data(&envelope, LossReason::NetworkError);
            }
        }
    }
}

/// Whether every item of `envelope` is currently rate limited. Sentry filters
/// item by item; here an envelope is sent unless all of it is held back.
fn all_rate_limited(limits: &RateLimiter, envelope: &Envelope) -> bool {
    envelope
        .items()
        .all(|item| limits.is_disabled(category_of(item)).is_some())
}

fn category_of(item: &EnvelopeItem) -> RateLimitingCategory {
    match item {
        EnvelopeItem::Event(_) => RateLimitingCategory::Error,
        EnvelopeItem::SessionUpdate(_) | EnvelopeItem::SessionAggregates(_) => {
            RateLimitingCategory::Session
        }
        EnvelopeItem::Transaction(_) => RateLimitingCategory::Transaction,
        EnvelopeItem::Attachment(_) => RateLimitingCategory::Attachment,
        EnvelopeItem::ItemContainer(ItemContainer::Logs(_)) => RateLimitingCategory::LogItem,
        EnvelopeItem::ItemContainer(ItemContainer::Metrics(_)) => {
            RateLimitingCategory::TraceMetric
        }
        _ => RateLimitingCategory::Any,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{Receiver as Rx, channel};

    use super::*;

    /// Reads one HTTP request (headers, then `Content-Length` bytes of body).
    fn read_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let read = stream.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buf[..read]);
            if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if data.len() >= end + 4 + length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&data).into_owned()
    }

    /// Answers each request with `responses` in turn (the last one repeats),
    /// and sends what it read to the returned receiver. Returns the DSN.
    fn serve(responses: Vec<&'static str>) -> (String, Rx<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = channel();
        thread::spawn(move || {
            for (index, stream) in listener.incoming().enumerate() {
                let mut stream = stream.unwrap();
                let _ = sender.send(read_request(&mut stream));
                let response = responses[index.min(responses.len() - 1)];
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (format!("http://public@127.0.0.1:{port}/1"), receiver)
    }

    fn client_for(dsn: &str, http: &HttpClient) -> sentry::Client {
        let mut options = sentry::ClientOptions::default();
        options.dsn = Some(dsn.parse().unwrap());
        options.transport = Some(Arc::new(HttpTransportFactory::new(http.clone())));
        sentry::Client::from_config(options)
    }

    fn event(message: &str) -> sentry::protocol::Event<'static> {
        let mut event = sentry::protocol::Event::new();
        event.message = Some(message.into());
        event
    }

    #[test]
    fn an_envelope_is_posted_to_the_envelope_api_with_the_auth_header() {
        let (dsn, requests) = serve(vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"]);
        let http = HttpClient::start().unwrap();
        let client = client_for(&dsn, &http);

        client.capture_event(event("it broke"), None);
        assert!(client.flush(Some(Duration::from_secs(5))));

        let seen = requests.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(seen.starts_with("POST /api/1/envelope/ "), "{seen}");
        assert!(seen.contains("sentry_key=public"), "{seen}");
        assert!(seen.contains("it broke"), "{seen}");
    }

    #[test]
    fn a_429_with_retry_after_stops_further_sends_for_a_while() {
        let (dsn, requests) = serve(vec![
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let http = HttpClient::start().unwrap();
        let client = client_for(&dsn, &http);

        client.capture_event(event("first"), None);
        assert!(client.flush(Some(Duration::from_secs(5))));
        client.capture_event(event("second"), None);
        assert!(client.flush(Some(Duration::from_secs(5))));

        requests.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(requests.recv_timeout(Duration::from_millis(300)).is_err());
    }

    #[test]
    fn a_rate_limit_header_for_errors_holds_back_error_envelopes_only() {
        let (dsn, requests) = serve(vec![
            "HTTP/1.1 200 OK\r\nX-Sentry-Rate-Limits: 60:error:scope\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let http = HttpClient::start().unwrap();
        let client = client_for(&dsn, &http);

        client.capture_event(event("first"), None);
        assert!(client.flush(Some(Duration::from_secs(5))));
        client.capture_event(event("second"), None);
        assert!(client.flush(Some(Duration::from_secs(5))));

        requests.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(requests.recv_timeout(Duration::from_millis(300)).is_err());
    }
}
