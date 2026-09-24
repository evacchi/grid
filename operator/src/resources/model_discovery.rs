//! Bounded polling and parsing for served-model discovery.

use std::{collections::BTreeSet, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use serde::Deserialize;

use crate::{
    crd::inference_provider::ModelDiscoveryConfig,
    resources::tls_backend::{ClientTlsConfig, build_custom_tls_connector, build_native_connector},
};

/// Maximum number of models accepted from one provider.
pub(crate) const MAX_MODELS: usize = 256;
/// Maximum UTF-8 byte length of one model ID.
const MAX_MODEL_ID_BYTES: usize = 256;
/// Maximum bytes read from one model-list response.
const MAX_RESPONSE_BYTES: usize = 128 * 1024;

/// A safe, machine-readable discovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiscoveryFailure {
    /// Endpoint or configuration is invalid.
    InvalidConfig,
    /// Request could not complete, including DNS and TLS failures.
    Transport,
    /// Request exceeded its timeout.
    Timeout,
    /// Endpoint returned a non-success status.
    HttpStatus,
    /// Response exceeded the byte limit.
    TooLarge,
    /// Response JSON or model IDs are invalid.
    InvalidResponse,
}

impl DiscoveryFailure {
    /// Stable reason written to `InferenceProvider.status.modelDiscovery`.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "InvalidConfig",
            Self::Transport => "Transport",
            Self::Timeout => "Timeout",
            Self::HttpStatus => "HttpStatus",
            Self::TooLarge => "TooLarge",
            Self::InvalidResponse => "InvalidResponse",
        }
    }
}

/// OpenAI-compatible model-list envelope.
#[derive(Deserialize)]
struct ModelsResponse {
    /// Returned model entries.
    data: Vec<ModelEntry>,
}

/// One model-list item.
#[derive(Deserialize)]
struct ModelEntry {
    /// Raw served-model identifier.
    id: String,
}

/// Build the OpenAI-compatible model-list URL from the configured base.
pub(crate) fn models_url(
    provider_endpoint: &str,
    config: &ModelDiscoveryConfig,
) -> Result<http::Uri, DiscoveryFailure> {
    let base = config
        .endpoint
        .as_deref()
        .unwrap_or(provider_endpoint)
        .trim_end_matches('/');
    let url = format!("{base}/v1/models");
    let uri = url
        .parse::<http::Uri>()
        .map_err(|_error| DiscoveryFailure::InvalidConfig)?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return Err(DiscoveryFailure::InvalidConfig);
    }
    Ok(uri)
}

/// Parse and normalize a bounded OpenAI-compatible model-list response.
pub(crate) fn parse_models(body: &[u8]) -> Result<Vec<String>, DiscoveryFailure> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DiscoveryFailure::TooLarge);
    }
    let response: ModelsResponse = serde_json::from_slice(body).map_err(|_error| DiscoveryFailure::InvalidResponse)?;
    if response.data.len() > MAX_MODELS {
        return Err(DiscoveryFailure::TooLarge);
    }
    let mut models = BTreeSet::new();
    for entry in response.data {
        if entry.id.trim().is_empty() || entry.id.len() > MAX_MODEL_ID_BYTES || entry.id.trim() != entry.id {
            return Err(DiscoveryFailure::InvalidResponse);
        }
        if !models.insert(entry.id) {
            return Err(DiscoveryFailure::InvalidResponse);
        }
    }
    Ok(models.into_iter().collect())
}

/// Poll one provider's `GET /v1/models` endpoint with bounded time and body size.
///
/// The optional bearer token is used only for this request and is never
/// included in the returned result or error.
#[expect(
    clippy::too_many_lines,
    reason = "TLS connector, bounded request, and model parsing form one poll"
)]
pub(crate) async fn poll_models(
    uri: http::Uri,
    timeout: Duration,
    tls_config: Option<ClientTlsConfig>,
    bearer_token: Option<&str>,
) -> Result<Vec<String>, DiscoveryFailure> {
    if tls_config.is_some() && uri.scheme_str() != Some("https") {
        return Err(DiscoveryFailure::InvalidConfig);
    }
    let connector = if let Some(config) = &tls_config {
        build_custom_tls_connector(config)
    } else {
        build_native_connector()
    }
    .map_err(|_error| DiscoveryFailure::InvalidConfig)?;
    let client: HyperClient<_, Empty<Bytes>> = HyperClient::builder(TokioExecutor::new()).build(connector);

    let mut request = http::Request::builder().method(http::Method::GET).uri(uri);
    if let Some(token) = bearer_token {
        let value = http::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_error| DiscoveryFailure::InvalidConfig)?;
        request = request.header(http::header::AUTHORIZATION, value);
    }
    let request = request
        .body(Empty::<Bytes>::new())
        .map_err(|_error| DiscoveryFailure::InvalidConfig)?;

    let fetch = async {
        let response = client
            .request(request)
            .await
            .map_err(|_error| DiscoveryFailure::Transport)?;
        if !response.status().is_success() {
            return Err(DiscoveryFailure::HttpStatus);
        }
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| {
                if error.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                    DiscoveryFailure::TooLarge
                } else {
                    DiscoveryFailure::Transport
                }
            })?
            .to_bytes();
        parse_models(&body)
    };
    tokio::time::timeout(timeout, fetch)
        .await
        .map_err(|_elapsed| DiscoveryFailure::Timeout)?
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, http::StatusCode, routing::get};

    use super::*;

    #[test]
    fn parses_sorted_models_and_empty_success() {
        let models = parse_models(br#"{"data":[{"id":"z"},{"id":"a"}]}"#).unwrap_or_else(|_| std::process::abort());
        assert_eq!(models, vec!["a", "z"]);
        assert_eq!(parse_models(br#"{"data":[]}"#), Ok(Vec::new()));
    }

    #[test]
    fn rejects_malformed_and_duplicate_models_without_clearing() {
        assert_eq!(
            parse_models(br#"{"data":[{"id":"a"},{"id":"a"}]}"#),
            Err(DiscoveryFailure::InvalidResponse)
        );
        assert_eq!(
            parse_models(br#"{"data":[{"id":" "}]}"#),
            Err(DiscoveryFailure::InvalidResponse)
        );
        assert_eq!(parse_models(br#"{"wrong":[]}"#), Err(DiscoveryFailure::InvalidResponse));
        assert_eq!(
            parse_models(br#"{"data":null}"#),
            Err(DiscoveryFailure::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn polls_each_endpoint_with_bearer_auth_and_reports_http_error() {
        let app = Router::new().route(
            "/v1/models",
            get(|headers: http::HeaderMap| async move {
                if headers
                    .get(http::header::AUTHORIZATION)
                    .is_some_and(|value| value == "Bearer secret")
                {
                    (StatusCode::OK, Json(serde_json::json!({"data": [{"id": "model-a"}]})))
                } else {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({"error": "scaled to zero"})),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|_| std::process::abort());
        let address = listener.local_addr().unwrap_or_else(|_| std::process::abort());
        let server = tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let uri = format!("http://{address}/v1/models")
            .parse::<http::Uri>()
            .unwrap_or_else(|_| std::process::abort());
        let success = poll_models(uri.clone(), Duration::from_secs(2), None, Some("secret")).await;
        assert_eq!(success, Ok(vec!["model-a".to_owned()]));
        let failure = poll_models(uri, Duration::from_secs(2), None, None).await;
        assert_eq!(failure, Err(DiscoveryFailure::HttpStatus));
        server.abort();
    }
}
