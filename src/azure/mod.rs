//! Azure helpers: read/write Cosmos DB items directly, and invoke Azure
//! Functions over HTTP.

mod cosmos;
mod functions;

use std::fmt;

pub use cosmos::Cosmos;
pub use functions::{FunctionAuth, FunctionClient};

/// Error returned by the Azure helpers in this module.
#[derive(Debug)]
pub enum AzureError {
    /// The Cosmos endpoint is not a valid account endpoint URL.
    InvalidEndpoint(String),
    /// Credentials could not be created or a token could not be acquired.
    Credential(azure_core::Error),
    /// A Cosmos DB request failed.
    Cosmos(azure_data_cosmos::CosmosError),
    /// The HTTP request to a function could not be sent or its response read.
    Http(reqwest::Error),
    /// The function answered with a non-success HTTP status.
    Function {
        status: u16,
        /// The response body, which usually describes the error.
        body: Vec<u8>,
    },
}

impl fmt::Display for AzureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AzureError::InvalidEndpoint(endpoint) => {
                write!(f, "invalid cosmos endpoint `{endpoint}`")
            }
            AzureError::Credential(err) => write!(f, "azure credential error: {err}"),
            AzureError::Cosmos(err) => write!(f, "cosmos request failed: {err}"),
            AzureError::Http(err) => write!(f, "function request failed: {err}"),
            AzureError::Function { status, body } => write!(
                f,
                "function returned HTTP {status}: {}",
                String::from_utf8_lossy(body)
            ),
        }
    }
}

impl std::error::Error for AzureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AzureError::Credential(err) => Some(err),
            AzureError::Cosmos(err) => Some(err),
            AzureError::Http(err) => Some(err),
            AzureError::InvalidEndpoint(_) | AzureError::Function { .. } => None,
        }
    }
}
