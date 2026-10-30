use std::sync::Arc;

use azure_core::credentials::TokenCredential;

use super::AzureError;

/// How to authenticate a request to an Azure Function.
#[derive(Clone)]
pub enum FunctionAuth {
    /// No credentials (the function's authorization level is `anonymous`).
    Anonymous,
    /// A function, host or master key, sent as the `x-functions-key` header.
    Key(String),
    /// A Microsoft Entra ID bearer token for `scope`, for function apps that
    /// use App Service Authentication. The scope is usually
    /// `api://<app-client-id>/.default`.
    Entra {
        credential: Arc<dyn TokenCredential>,
        scope: String,
    },
}

/// Invokes HTTP-triggered Azure Functions.
#[derive(Clone)]
pub struct FunctionClient {
    http: reqwest::Client,
    auth: FunctionAuth,
}

impl FunctionClient {
    pub fn new(auth: FunctionAuth) -> Self {
        Self { http: reqwest::Client::new(), auth }
    }

    /// Sends `body` (as `application/json`) with a `POST` to the function at
    /// `url`, e.g. `https://myapp.azurewebsites.net/api/my-function`, and
    /// returns the response body.
    ///
    /// Returns [`AzureError::Function`] for any non-2xx status.
    pub async fn invoke(
        &self,
        url: &str,
        body: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>, AzureError> {
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.into());

        request = match &self.auth {
            FunctionAuth::Anonymous => request,
            FunctionAuth::Key(key) => request.header("x-functions-key", key),
            FunctionAuth::Entra { credential, scope } => {
                let token = credential
                    .get_token(&[scope.as_str()], None)
                    .await
                    .map_err(AzureError::Credential)?;
                request.bearer_auth(token.token.secret())
            }
        };

        let response = request.send().await.map_err(AzureError::Http)?;
        let status = response.status();
        let body = response.bytes().await.map_err(AzureError::Http)?.to_vec();

        if status.is_success() {
            Ok(body)
        } else {
            Err(AzureError::Function { status: status.as_u16(), body })
        }
    }
}

#[cfg(test)]
mod tests {
    use azure_core::credentials::AccessToken;
    use azure_core::time::OffsetDateTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Serves one HTTP request with `status` and `response_body`, then returns
    /// the raw request text it received.
    async fn serve_once(
        status: &'static str,
        response_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/api/fn", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&received);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(received).unwrap()
        });
        (url, handle)
    }

    #[derive(Debug)]
    struct FakeCredential;

    #[async_trait::async_trait]
    impl TokenCredential for FakeCredential {
        async fn get_token(
            &self,
            scopes: &[&str],
            _options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            Ok(AccessToken::new(
                format!("token-for-{}", scopes.join(",")),
                OffsetDateTime::now_utc() + std::time::Duration::from_secs(3600),
            ))
        }
    }

    #[tokio::test]
    async fn posts_the_body_and_returns_the_response() {
        let (url, server) = serve_once("200 OK", r#"{"ok":true}"#).await;

        let response = FunctionClient::new(FunctionAuth::Anonymous)
            .invoke(&url, r#"{"a":1}"#)
            .await
            .unwrap();

        assert_eq!(response, br#"{"ok":true}"#);
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/fn "), "{request}");
        assert!(request.to_ascii_lowercase().contains("content-type: application/json"));
        assert!(request.ends_with(r#"{"a":1}"#));
        assert!(!request.to_ascii_lowercase().contains("x-functions-key"));
    }

    #[tokio::test]
    async fn sends_the_function_key() {
        let (url, server) = serve_once("200 OK", "").await;

        FunctionClient::new(FunctionAuth::Key("secret".into()))
            .invoke(&url, "{}")
            .await
            .unwrap();

        assert!(server.await.unwrap().to_ascii_lowercase().contains("x-functions-key: secret"));
    }

    #[tokio::test]
    async fn sends_an_entra_bearer_token() {
        let (url, server) = serve_once("200 OK", "").await;
        let auth = FunctionAuth::Entra {
            credential: Arc::new(FakeCredential),
            scope: "api://app/.default".into(),
        };

        FunctionClient::new(auth).invoke(&url, "{}").await.unwrap();

        assert!(
            server
                .await
                .unwrap()
                .to_ascii_lowercase()
                .contains("authorization: bearer token-for-api://app/.default")
        );
    }

    #[tokio::test]
    async fn maps_non_success_status_to_function_error() {
        let (url, _server) = serve_once("500 Internal Server Error", "boom").await;

        let err = FunctionClient::new(FunctionAuth::Anonymous)
            .invoke(&url, "{}")
            .await
            .unwrap_err();

        assert!(matches!(&err, AzureError::Function { status: 500, body } if body == b"boom"), "{err}");
    }
}
