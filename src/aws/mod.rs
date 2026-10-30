mod cloudwatch;

use std::fmt;

use aws_sdk_lambda::error::DisplayErrorContext;
use aws_sdk_lambda::primitives::Blob;

pub use cloudwatch::{CloudWatchError, CloudWatchLogsClient, LambdaReportRecord};

/// Error returned by [`LambdaClient::invoke`].
#[derive(Debug)]
pub enum LambdaError {
    /// The invoke request itself failed (credentials, network, permissions,
    /// unknown function, throttling, ...). Holds the full SDK error chain.
    Invoke(String),
    /// The function ran but reported an error (an unhandled exception, a
    /// timeout, ...).
    Function {
        /// Lambda's error kind, `"Handled"` or `"Unhandled"`.
        error_type: String,
        /// The response payload, which describes the error (usually JSON).
        payload: Vec<u8>,
    },
}

impl fmt::Display for LambdaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LambdaError::Invoke(message) => write!(f, "failed to invoke lambda: {message}"),
            LambdaError::Function { error_type, payload } => write!(
                f,
                "lambda function returned an error ({error_type}): {}",
                String::from_utf8_lossy(payload)
            ),
        }
    }
}

impl std::error::Error for LambdaError {}

/// Calls AWS Lambda functions directly through the AWS SDK.
#[derive(Debug, Clone)]
pub struct LambdaClient {
    client: aws_sdk_lambda::Client,
}

impl LambdaClient {
    /// Creates a client from the default AWS configuration: credentials and
    /// region come from the standard provider chain, e.g. the
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and
    /// `AWS_REGION` variables that GitHub Actions sets up through OIDC with
    /// `aws-actions/configure-aws-credentials`.
    pub async fn from_env() -> Self {
        let config = aws_config::load_from_env().await;
        Self::from_client(aws_sdk_lambda::Client::new(&config))
    }

    /// Wraps an already configured SDK client.
    pub fn from_client(client: aws_sdk_lambda::Client) -> Self {
        Self { client }
    }

    /// Invokes `function_name` (a name, ARN or partial ARN, optionally with a
    /// `:qualifier`) synchronously with `payload`, and returns the response
    /// payload.
    ///
    /// Returns [`LambdaError::Function`] if the function itself reports an
    /// error, since Lambda answers those with a successful HTTP status.
    pub async fn invoke(
        &self,
        function_name: &str,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>, LambdaError> {
        let output = self
            .client
            .invoke()
            .function_name(function_name)
            .payload(Blob::new(payload))
            .send()
            .await
            .map_err(|err| LambdaError::Invoke(DisplayErrorContext(&err).to_string()))?;

        let payload = output.payload.map(Blob::into_inner).unwrap_or_default();
        match output.function_error {
            Some(error_type) => Err(LambdaError::Function { error_type, payload }),
            None => Ok(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_lambda::operation::invoke::InvokeOutput;
    use aws_smithy_mocks::{mock, mock_client};

    use super::*;

    fn client_for(rule: &aws_smithy_mocks::Rule) -> LambdaClient {
        LambdaClient::from_client(mock_client!(aws_sdk_lambda, [rule]))
    }

    #[tokio::test]
    async fn returns_the_response_payload() {
        let rule = mock!(aws_sdk_lambda::Client::invoke)
            .match_requests(|req| {
                req.function_name() == Some("my-fn")
                    && req.payload().map(|p| p.as_ref()) == Some(br#"{"a":1}"#.as_slice())
            })
            .then_output(|| {
                InvokeOutput::builder()
                    .status_code(200)
                    .payload(Blob::new(br#"{"ok":true}"#.to_vec()))
                    .build()
            });

        let response = client_for(&rule).invoke("my-fn", br#"{"a":1}"#.to_vec()).await.unwrap();

        assert_eq!(response, br#"{"ok":true}"#);
        assert_eq!(rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn returns_empty_payload_when_response_has_none() {
        let rule = mock!(aws_sdk_lambda::Client::invoke)
            .then_output(|| InvokeOutput::builder().status_code(200).build());

        let response = client_for(&rule).invoke("my-fn", Vec::new()).await.unwrap();

        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn maps_function_errors() {
        let rule = mock!(aws_sdk_lambda::Client::invoke).then_output(|| {
            InvokeOutput::builder()
                .status_code(200)
                .function_error("Unhandled")
                .payload(Blob::new(br#"{"errorMessage":"boom"}"#.to_vec()))
                .build()
        });

        let err = client_for(&rule).invoke("my-fn", Vec::new()).await.unwrap_err();

        match err {
            LambdaError::Function { error_type, payload } => {
                assert_eq!(error_type, "Unhandled");
                assert_eq!(payload, br#"{"errorMessage":"boom"}"#);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn maps_request_failures() {
        let rule = mock!(aws_sdk_lambda::Client::invoke).then_error(|| {
            aws_sdk_lambda::operation::invoke::InvokeError::ResourceNotFoundException(
                aws_sdk_lambda::types::error::ResourceNotFoundException::builder()
                    .message("Function not found")
                    .build(),
            )
        });

        let err = client_for(&rule).invoke("missing", Vec::new()).await.unwrap_err();

        assert!(matches!(&err, LambdaError::Invoke(message) if message.contains("Function not found")), "{err}");
    }
}
