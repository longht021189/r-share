use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::StatusCode;
use azure_data_cosmos::options::Region;
use azure_data_cosmos::{AccountEndpoint, AccountReference, CosmosClient, RoutingStrategy};
use azure_identity::DeveloperToolsCredential;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::AzureError;

/// Reads and writes Azure Cosmos DB (NoSQL API) items directly, using
/// Microsoft Entra ID authentication (no account keys).
#[derive(Clone)]
pub struct Cosmos {
    client: CosmosClient,
}

impl Cosmos {
    /// Connects to the account at `endpoint` (e.g.
    /// `https://myaccount.documents.azure.com/`), preferring the Azure region
    /// closest to `region` (e.g. `"East US"`).
    pub async fn connect(
        endpoint: &str,
        region: &str,
        credential: Arc<dyn TokenCredential>,
    ) -> Result<Self, AzureError> {
        let endpoint: AccountEndpoint = endpoint
            .parse()
            .map_err(|_| AzureError::InvalidEndpoint(endpoint.to_string()))?;
        let account = AccountReference::with_credential(endpoint, credential);
        let client = CosmosClient::builder()
            .build(account, RoutingStrategy::ProximityTo(Region::from(region.to_string())))
            .await
            .map_err(AzureError::Cosmos)?;
        Ok(Self { client })
    }

    /// Like [`Cosmos::connect`], authenticating as the identity signed in to
    /// the Azure CLI (`az login`) or Azure Developer CLI (`azd auth login`).
    ///
    /// This is what runs on a developer machine and in GitHub Actions after
    /// `azure/login` (OIDC). The identity needs a Cosmos DB data-plane role,
    /// e.g. "Cosmos DB Built-in Data Contributor".
    pub async fn connect_with_developer_tools(
        endpoint: &str,
        region: &str,
    ) -> Result<Self, AzureError> {
        let credential = DeveloperToolsCredential::new(None).map_err(AzureError::Credential)?;
        Self::connect(endpoint, region, credential).await
    }

    /// Reads the item `id` in `partition_key`, or `None` if it does not exist.
    pub async fn read<T: DeserializeOwned>(
        &self,
        database: &str,
        container: &str,
        partition_key: &str,
        id: &str,
    ) -> Result<Option<T>, AzureError> {
        let container = self.container(database, container).await?;
        match container.read_item(partition_key.to_string(), id, None).await {
            Ok(response) => response.into_model().map(Some).map_err(AzureError::Cosmos),
            Err(err) if err.status().status_code() == StatusCode::NotFound => Ok(None),
            Err(err) => Err(AzureError::Cosmos(err)),
        }
    }

    /// Creates the item, or replaces it if `id` already exists in
    /// `partition_key` (upsert).
    ///
    /// `item` must serialize to a JSON object whose `id` is `id` and which
    /// contains the container's partition key property with value
    /// `partition_key`.
    pub async fn write<T: Serialize>(
        &self,
        database: &str,
        container: &str,
        partition_key: &str,
        id: &str,
        item: &T,
    ) -> Result<(), AzureError> {
        let container = self.container(database, container).await?;
        container
            .upsert_item(partition_key.to_string(), id, item, None)
            .await
            .map(drop)
            .map_err(AzureError::Cosmos)
    }

    async fn container(
        &self,
        database: &str,
        container: &str,
    ) -> Result<azure_data_cosmos::ContainerClient, AzureError> {
        self.client
            .database_client(database)
            .container_client(container, None)
            .await
            .map_err(AzureError::Cosmos)
    }
}
