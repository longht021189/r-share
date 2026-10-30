use std::fmt;
use std::sync::LazyLock;

use aws_sdk_cloudwatchlogs::error::DisplayErrorContext;
use regex::Regex;

/// Error returned by [`CloudWatchLogsClient::collect_lambda_reports`].
#[derive(Debug)]
pub enum CloudWatchError {
    /// The `FilterLogEvents` request itself failed (credentials, network,
    /// permissions, unknown log group, throttling, ...). Holds the full SDK
    /// error chain.
    Filter(String),
}

impl fmt::Display for CloudWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudWatchError::Filter(message) => write!(f, "failed to filter log events: {message}"),
        }
    }
}

impl std::error::Error for CloudWatchError {}

/// One Lambda invocation's `REPORT` log line, parsed out of CloudWatch Logs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LambdaReportRecord {
    /// When CloudWatch received the log event, in milliseconds since the
    /// epoch. Feed `max(timestamp_ms) + 1` back in as the next run's
    /// `start_time_ms` to collect only newly logged invocations.
    pub timestamp_ms: i64,
    /// Which Lambda function logged this invocation. For a log group shared
    /// by several functions (its log streams look like
    /// `2026/10/01/my-function[$LATEST]f9dc3c83...`), this is parsed out of
    /// `log_stream_name` -- the REPORT line itself never says which
    /// function logged it. For a log group dedicated to one function
    /// (streams look like `2026/10/01/[$LATEST]f9dc3c83...`, no function
    /// segment), this falls back to the `log_group_name` the caller passed
    /// to [`CloudWatchLogsClient::collect_lambda_reports`].
    pub function_name: String,
    /// The CloudWatch log stream this was read from, e.g.
    /// `2026/10/01/[$LATEST]f9dc3c83f5c04e4e862afde0db2ef55a` or
    /// `2026/10/01/my-function[$LATEST]f9dc3c83...`.
    pub log_stream_name: String,
    pub request_id: String,
    pub duration_ms: f64,
    pub billed_duration_ms: u64,
    pub memory_size_mb: u64,
    pub max_memory_used_mb: u64,
    /// Only present on cold starts.
    pub init_duration_ms: Option<f64>,
}

/// Reads AWS Lambda `REPORT` lines directly out of CloudWatch Logs through
/// the AWS SDK.
#[derive(Debug, Clone)]
pub struct CloudWatchLogsClient {
    client: aws_sdk_cloudwatchlogs::Client,
}

impl CloudWatchLogsClient {
    /// Creates a client from the default AWS configuration: credentials and
    /// region come from the standard provider chain, e.g. the
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and
    /// `AWS_REGION` variables that GitHub Actions sets up through OIDC with
    /// `aws-actions/configure-aws-credentials`.
    pub async fn from_env() -> Self {
        let config = aws_config::load_from_env().await;
        Self::from_client(aws_sdk_cloudwatchlogs::Client::new(&config))
    }

    /// Wraps an already configured SDK client.
    pub fn from_client(client: aws_sdk_cloudwatchlogs::Client) -> Self {
        Self { client }
    }

    /// Collects and parses every Lambda `REPORT` line logged to
    /// `log_group_name` (e.g. `/aws/lambda/<function-name>`) between
    /// `start_time_ms` and `end_time_ms`, both milliseconds since the epoch.
    /// Per the CloudWatch API, both bounds are inclusive: an event with
    /// timestamp exactly `start_time_ms` or exactly `end_time_ms` is
    /// included. Callers chaining adjacent, non-overlapping windows (e.g.
    /// one call per day) should subtract 1 from the next window's bound to
    /// avoid double-counting an event that lands exactly on it. Pass `None`
    /// for either bound to leave it open.
    ///
    /// Paginates internally until every matching event has been fetched.
    /// Log lines that aren't a recognizable `REPORT` line are silently
    /// skipped, so this is safe to point at a log group that also carries
    /// other output (e.g. the function's own `println!`/`console.log`).
    pub async fn collect_lambda_reports(
        &self,
        log_group_name: &str,
        start_time_ms: Option<i64>,
        end_time_ms: Option<i64>,
    ) -> Result<Vec<LambdaReportRecord>, CloudWatchError> {
        let mut records = Vec::new();
        let mut next_token = None;

        loop {
            let mut request = self
                .client
                .filter_log_events()
                .log_group_name(log_group_name)
                .filter_pattern("REPORT RequestId");

            if let Some(start_time_ms) = start_time_ms {
                request = request.start_time(start_time_ms);
            }
            if let Some(end_time_ms) = end_time_ms {
                request = request.end_time(end_time_ms);
            }
            if let Some(next_token) = next_token {
                request = request.next_token(next_token);
            }

            let output = request
                .send()
                .await
                .map_err(|err| CloudWatchError::Filter(DisplayErrorContext(&err).to_string()))?;

            for event in output.events() {
                if let (Some(timestamp_ms), Some(log_stream_name), Some(message)) =
                    (event.timestamp(), event.log_stream_name(), event.message())
                {
                    records.extend(parse_report_line(timestamp_ms, log_group_name, log_stream_name, message));
                }
            }

            next_token = output.next_token().map(str::to_owned);
            if next_token.is_none() {
                break;
            }
        }

        Ok(records)
    }
}

/// Matches lines like:
/// `REPORT RequestId: 52fdfc07-... Duration: 10.11 ms Billed Duration: 11 ms
/// Memory Size: 128 MB Max Memory Used: 56 MB Init Duration: 128.38 ms`
/// (the real separators are tabs; `\s+` matches those too). `Init Duration`
/// is only present on cold starts, hence the trailing optional group.
static REPORT_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"REPORT RequestId:\s*(?P<request_id>\S+)\s+Duration:\s*(?P<duration>[\d.]+)\s*ms\s+Billed Duration:\s*(?P<billed_duration>\d+)\s*ms\s+Memory Size:\s*(?P<memory_size>\d+)\s*MB\s+Max Memory Used:\s*(?P<max_memory_used>\d+)\s*MB(?:\s+Init Duration:\s*(?P<init_duration>[\d.]+)\s*ms)?",
    )
    .expect("REPORT_LINE is a fixed, valid pattern")
});

fn parse_report_line(
    timestamp_ms: i64,
    log_group_name: &str,
    log_stream_name: &str,
    message: &str,
) -> Option<LambdaReportRecord> {
    let captures = REPORT_LINE.captures(message)?;
    let field = |name: &str| captures.name(name).unwrap().as_str();
    let function_name = function_name_from_log_stream(log_stream_name)
        .unwrap_or(log_group_name)
        .to_owned();

    Some(LambdaReportRecord {
        timestamp_ms,
        function_name,
        log_stream_name: log_stream_name.to_owned(),
        request_id: field("request_id").to_owned(),
        duration_ms: field("duration").parse().ok()?,
        billed_duration_ms: field("billed_duration").parse().ok()?,
        memory_size_mb: field("memory_size").parse().ok()?,
        max_memory_used_mb: field("max_memory_used").parse().ok()?,
        init_duration_ms: captures.name("init_duration").and_then(|m| m.as_str().parse().ok()),
    })
}

/// Matches the `<function-name>[` segment of a log stream name for a log
/// group shared by several functions, e.g.
/// `2026/10/01/my-function[$LATEST]f9dc3c83...` -> `my-function`. A log
/// group dedicated to a single function has no such segment -- its streams
/// look like `2026/10/01/[$LATEST]f9dc3c83...`, starting with `[` right
/// after the date -- so this simply doesn't match there.
static LOG_STREAM_FUNCTION_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\d{4}/\d{2}/\d{2}/([^\[]+)\[").expect("LOG_STREAM_FUNCTION_NAME is a fixed, valid pattern")
});

fn function_name_from_log_stream(log_stream_name: &str) -> Option<&str> {
    Some(LOG_STREAM_FUNCTION_NAME.captures(log_stream_name)?.get(1)?.as_str())
}

#[cfg(test)]
mod tests {
    use aws_sdk_cloudwatchlogs::operation::filter_log_events::FilterLogEventsOutput;
    use aws_sdk_cloudwatchlogs::types::FilteredLogEvent;
    use aws_smithy_mocks::{mock, mock_client};

    use super::*;

    fn client_for(rule: &aws_smithy_mocks::Rule) -> CloudWatchLogsClient {
        CloudWatchLogsClient::from_client(mock_client!(aws_sdk_cloudwatchlogs, [rule]))
    }

    #[test]
    fn parses_a_cold_start_report_line() {
        let message = "REPORT RequestId: 52fdfc07-2182-454f-963f-5f0f9a621d72\tDuration: 10.11 ms\tBilled Duration: 11 ms\tMemory Size: 128 MB\tMax Memory Used: 56 MB\tInit Duration: 128.38 ms\t";

        let record = parse_report_line(
            1_700_000_000_000,
            "/aws/lambda/my-fn",
            "2026/10/01/[$LATEST]f9dc3c83f5c04e4e862afde0db2ef55a",
            message,
        )
        .unwrap();

        assert_eq!(
            record,
            LambdaReportRecord {
                timestamp_ms: 1_700_000_000_000,
                function_name: "/aws/lambda/my-fn".to_owned(),
                log_stream_name: "2026/10/01/[$LATEST]f9dc3c83f5c04e4e862afde0db2ef55a".to_owned(),
                request_id: "52fdfc07-2182-454f-963f-5f0f9a621d72".to_owned(),
                duration_ms: 10.11,
                billed_duration_ms: 11,
                memory_size_mb: 128,
                max_memory_used_mb: 56,
                init_duration_ms: Some(128.38),
            }
        );
    }

    #[test]
    fn parses_a_warm_report_line_without_init_duration() {
        let message = "REPORT RequestId: abc\tDuration: 1.00 ms\tBilled Duration: 1 ms\tMemory Size: 256 MB\tMax Memory Used: 70 MB\t";

        let record = parse_report_line(0, "/aws/lambda/my-fn", "stream", message).unwrap();

        assert_eq!(record.init_duration_ms, None);
        assert_eq!(record.request_id, "abc");
    }

    #[test]
    fn ignores_lines_that_are_not_report_lines() {
        assert!(parse_report_line(0, "lg", "stream", "START RequestId: abc Version: $LATEST").is_none());
        assert!(parse_report_line(0, "lg", "stream", "user log message, nothing to do with REPORT").is_none());
    }

    #[test]
    fn function_name_falls_back_to_the_log_group_for_a_dedicated_log_group() {
        let message = "REPORT RequestId: abc\tDuration: 1.00 ms\tBilled Duration: 1 ms\tMemory Size: 256 MB\tMax Memory Used: 70 MB\t";

        let record = parse_report_line(
            0,
            "/aws/lambda/my-fn",
            "2026/10/01/[$LATEST]f9dc3c83f5c04e4e862afde0db2ef55a",
            message,
        )
        .unwrap();

        assert_eq!(record.function_name, "/aws/lambda/my-fn");
    }

    #[test]
    fn function_name_is_parsed_out_of_a_shared_log_group_stream() {
        let message = "REPORT RequestId: abc\tDuration: 1.00 ms\tBilled Duration: 1 ms\tMemory Size: 256 MB\tMax Memory Used: 70 MB\t";

        let record = parse_report_line(
            0,
            "/stg/lambda-platform-log-lines",
            "2026/09/29/exo-worker-stg-watchdog-cron[$LATEST]ad65513aad0f4eafb65ed21796cdab8b",
            message,
        )
        .unwrap();

        assert_eq!(record.function_name, "exo-worker-stg-watchdog-cron");
    }

    #[test]
    fn function_name_matches_a_real_lambda_platform_log_lines_stream() {
        let message = "REPORT RequestId: abc\tDuration: 1.00 ms\tBilled Duration: 1 ms\tMemory Size: 256 MB\tMax Memory Used: 70 MB\t";

        let record = parse_report_line(
            0,
            "/stg/lambda-platform-log-lines",
            "2026/10/03/exo-worker-stg-watchdog-cron[$LATEST]63054f2a167443a89647f696eae7ec3c",
            message,
        )
        .unwrap();

        assert_eq!(record.function_name, "exo-worker-stg-watchdog-cron");
    }

    #[tokio::test]
    async fn collects_report_lines_across_pages() {
        let rule = mock!(aws_sdk_cloudwatchlogs::Client::filter_log_events)
            .match_requests(|req| req.log_group_name() == Some("/aws/lambda/my-fn") && req.next_token().is_none())
            .then_output(|| {
                FilterLogEventsOutput::builder()
                    .events(
                        FilteredLogEvent::builder()
                            .timestamp(1)
                            .log_stream_name("2026/10/01/[$LATEST]aaa")
                            .message("REPORT RequestId: a\tDuration: 1.0 ms\tBilled Duration: 1 ms\tMemory Size: 128 MB\tMax Memory Used: 50 MB\t")
                            .build(),
                    )
                    .next_token("page-2")
                    .build()
            });
        let rule_page_2 = mock!(aws_sdk_cloudwatchlogs::Client::filter_log_events)
            .match_requests(|req| req.next_token() == Some("page-2"))
            .then_output(|| {
                FilterLogEventsOutput::builder()
                    .events(
                        FilteredLogEvent::builder()
                            .timestamp(2)
                            .log_stream_name("2026/10/01/[$LATEST]bbb")
                            .message("REPORT RequestId: b\tDuration: 2.0 ms\tBilled Duration: 2 ms\tMemory Size: 128 MB\tMax Memory Used: 60 MB\t")
                            .build(),
                    )
                    .build()
            });

        let client = CloudWatchLogsClient::from_client(mock_client!(
            aws_sdk_cloudwatchlogs,
            [&rule, &rule_page_2]
        ));

        let records = client
            .collect_lambda_reports("/aws/lambda/my-fn", None, None)
            .await
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request_id, "a");
        assert_eq!(records[1].request_id, "b");
    }

    #[tokio::test]
    async fn maps_request_failures() {
        let rule = mock!(aws_sdk_cloudwatchlogs::Client::filter_log_events).then_error(|| {
            aws_sdk_cloudwatchlogs::operation::filter_log_events::FilterLogEventsError::ResourceNotFoundException(
                aws_sdk_cloudwatchlogs::types::error::ResourceNotFoundException::builder()
                    .message("The specified log group does not exist")
                    .build(),
            )
        });

        let err = client_for(&rule)
            .collect_lambda_reports("/aws/lambda/missing", None, None)
            .await
            .unwrap_err();

        assert!(
            matches!(&err, CloudWatchError::Filter(message) if message.contains("does not exist")),
            "{err}"
        );
    }
}
