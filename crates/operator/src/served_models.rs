//! Served models discovered from this site's providers, held in memory.
//!
//! A discovery round runs on its own cadence, like the signals scraper:
//!
//! ```text
//!   every interval
//!     list InferenceProviders with spec.modelDiscovery
//!     poll each source (bounded concurrency)
//!     ServedModelStore::refresh
//!       success               → replace set, renew deadline
//!       failure               → keep set, deadline unchanged
//!       provider not polled   → drop set
//!       deadline passed       → drop set
//!     patch the discovery-owned status fields
//!       changed set           → status.servedModels, absent once expired
//!       failure reason        → status.modelDiscoveryError
//! ```
//!
//! Freshness is absence: a set no poll renews expires after `ttl`, so a stale
//! set fails closed and no reader compares one clock against another.
//! `status.servedModels` is the durable hand-off to reconcile: writing it
//! advances `resourceVersion`, so the CRDT revision of the gossiped provider
//! record advances with the set.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::{StreamExt as _, stream};
use kube::{
    Client,
    api::{Api, ListParams, Patch, PatchParams},
};

use crate::{
    crd::inference_provider::{InferenceProvider, InferenceProviderStatus, ModelDiscoveryConfig, OpenAiModelsSource},
    error::OperatorError,
    metrics,
    resources::{
        credentials::{self, CredentialPlan, CredentialResolver as _, KubernetesSecretResolver},
        endpoint_tls,
        model_discovery::{self, DiscoveryError, ModelSource as _, OpenAiModels, ServedModels},
    },
};

// ---------------------------------------------------------------------------
// DiscoveryConfig
// ---------------------------------------------------------------------------

/// Cadence and bounds of discovery rounds.
#[derive(Clone, Copy, Debug)]
pub struct DiscoveryConfig {
    /// Time between rounds.
    pub interval: Duration,

    /// Bound on one provider poll, including reading the response.
    pub timeout: Duration,

    /// How long a discovered set is held without a successful poll.
    pub ttl: Duration,

    /// Maximum providers polled at once.
    pub concurrency: usize,
}

impl Default for DiscoveryConfig {
    /// 60s interval; a set survives two missed rounds (180s).
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            ttl: Duration::from_secs(180),
            concurrency: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// ServedModelStore
// ---------------------------------------------------------------------------

/// A provider's served-model set and when it stops being held.
#[derive(Debug)]
struct ServedModel {
    /// Validated model names.
    models: Arc<[String]>,

    /// Deadline after which the set is no longer served.
    expires_at: Instant,
}

/// The result of polling one named provider.
struct ProviderPoll(
    /// Models reported, or a failed poll.
    PollOutcome,
    /// `InferenceProvider` name.
    String,
);

/// The status-relevant outcome of one provider poll.
struct ProviderPollStatus {
    /// `InferenceProvider` name.
    name: String,
    /// Failure reason, or `None` after a successful poll.
    failure_reason: Option<&'static str>,
}

/// What one provider poll reported.
enum PollOutcome {
    /// The validated served-model set, including an empty set.
    Served(ServedModels),

    /// Polling failed; the last good set may remain held.
    Failed(PollError),
}

impl PollOutcome {
    /// Bounded failure reason, absent after a successful poll.
    fn failure_reason(&self) -> Option<&'static str> {
        match self {
            Self::Served(_) => None,
            Self::Failed(error) => Some(error.as_reason()),
        }
    }
}

/// Served-model sets keyed by `InferenceProvider` name.
///
/// Cheap to clone; clones share the same sets.
#[derive(Clone, Debug, Default)]
pub struct ServedModelStore {
    /// Provider name to its held set.
    inner: Arc<RwLock<BTreeMap<String, ServedModel>>>,
}

impl ServedModelStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Models `provider` serves, or `None` when unknown or expired.
    #[must_use]
    pub fn models(&self, provider: &str) -> Option<Arc<[String]>> {
        let now = Instant::now();
        let guard = self.inner.read().ok()?;
        guard
            .get(provider)
            .filter(|held| held.expires_at > now)
            .map(|held| Arc::clone(&held.models))
    }

    /// Apply one round of poll results.
    ///
    /// `updated` holds every provider polled this round: a served set replaces
    /// the old one, while a failed poll keeps it until expiry. Providers absent
    /// from `updated` are no longer configured and are dropped.
    ///
    /// Changes, expirations, and drops are logged at `debug`.
    fn refresh(&self, updated: Vec<ProviderPoll>, now: Instant, ttl: Duration) {
        let expires_at = now.checked_add(ttl);
        let Ok(mut map) = self.inner.write() else {
            return;
        };

        prune_before_refresh(&mut map, &updated, now);
        for ProviderPoll(outcome, name) in updated {
            match outcome {
                PollOutcome::Served(discovered) => match expires_at {
                    Some(expires_at) => {
                        let models: Arc<[String]> = discovered.into_names().into();
                        tracing::debug!(name, ?models, "served models refreshed");
                        map.insert(name.clone(), ServedModel { models, expires_at });
                    },
                    None => {
                        tracing::warn!(name, ?ttl, "model discovery TTL exceeds the monotonic clock range");
                    },
                },
                PollOutcome::Failed(_) => {},
            }
        }
    }
}

/// Remove unpolled and expired entries before applying successful results.
fn prune_before_refresh(map: &mut BTreeMap<String, ServedModel>, updated: &[ProviderPoll], now: Instant) {
    map.retain(
        |provider: &String, served| match updated.iter().find(|ProviderPoll(_, p)| *p == *provider) {
            None => {
                tracing::debug!(provider, "served models dropped");
                false
            },
            Some(ProviderPoll(PollOutcome::Failed(_), _)) if served.expires_at <= now => {
                tracing::debug!(provider, "served models expired");
                false
            },
            Some(_) => served.expires_at > now,
        },
    );
}

// ---------------------------------------------------------------------------
// Discovery round
// ---------------------------------------------------------------------------

/// Field manager for discovery-owned status fields.
const DISCOVERY_FIELD_MANAGER: &str = "grid-model-discovery";

/// Poll every provider that opts into discovery and refresh `store`.
///
/// # Errors
///
/// Returns [`OperatorError`] when providers cannot be listed. A list failure
/// leaves `store` untouched. Status patch failures are logged per provider.
pub(crate) async fn discover(
    store: &ServedModelStore,
    client: &Client,
    config: &DiscoveryConfig,
) -> Result<(), OperatorError> {
    let api: Api<InferenceProvider> = Api::all(client.clone());
    let providers = api.list(&ListParams::default()).await?.items;

    let discoverable = providers.iter().filter_map(|provider| {
        let source = provider.spec.model_discovery.as_ref()?;
        Some((provider, source))
    });
    let polled = stream::iter(discoverable)
        .map(|(provider, source)| async move { poll(provider, source, client, config.timeout).await })
        .buffer_unordered(config.concurrency.max(1))
        .filter_map(|polled| async move { polled })
        .collect::<Vec<_>>()
        .await;

    let status_updates = polled
        .iter()
        .map(|ProviderPoll(outcome, name)| ProviderPollStatus {
            name: name.clone(),
            failure_reason: outcome.failure_reason(),
        })
        .collect::<Vec<_>>();
    store.refresh(polled, Instant::now(), config.ttl);
    publish_discovery_status(&api, &providers, store, &status_updates).await;
    Ok(())
}

/// Patch changed discovery-owned status: the failure reason and the served set.
///
/// `store` is read after this round's refresh, so an expired or dropped set
/// reads as absent and is cleared from the status.
async fn publish_discovery_status(
    api: &Api<InferenceProvider>,
    providers: &[InferenceProvider],
    store: &ServedModelStore,
    polled: &[ProviderPollStatus],
) {
    for provider in providers {
        if let Some(desired) = DiscoveryStatusPatch::for_provider(provider, store, polled)
            && let Err(error) = patch_discovery_status(api, &desired).await
        {
            tracing::warn!(provider = %desired.name, %error, "failed to patch model discovery status");
        }
    }
}

/// The discovery-owned status desired for one provider.
#[derive(Debug, PartialEq)]
struct DiscoveryStatusPatch {
    /// `InferenceProvider` name.
    name: String,

    /// Failure reason, or `None` after a successful poll.
    failure_reason: Option<&'static str>,

    /// Served-model set, or `None` when unknown, expired, or discovery is off.
    models: Option<Vec<String>>,
}

impl DiscoveryStatusPatch {
    /// Decide whether one provider's discovery status needs a patch.
    ///
    /// `None` when the current status already shows the desired failure reason
    /// and served-model set. The desired set is the store's effective set, which
    /// is absent for a provider whose discovery is disabled, never succeeded, or
    /// expired: absence is the fail-closed state. An empty set is present and
    /// distinct from absence.
    fn for_provider(
        provider: &InferenceProvider,
        store: &ServedModelStore,
        polled: &[ProviderPollStatus],
    ) -> Option<Self> {
        let name = provider.metadata.name.as_deref()?;
        let failure_reason = polled
            .iter()
            .find(|status| status.name == name)
            .and_then(|status| status.failure_reason);
        let models = provider
            .spec
            .model_discovery
            .as_ref()
            .and_then(|_| store.models(name))
            .map(|models| models.to_vec());
        let desired = DiscoveryStatusPatch {
            name: name.to_owned(),
            failure_reason,
            models,
        };
        let current = provider.status.as_ref();
        if desired.has_same_error(current) && desired.has_same_models(current) {
            return None;
        }
        Some(desired)
    }

    /// Whether `current` shows exactly this patch's served-model set.
    ///
    /// Model lists are compared as sets: poll response order is not stable,
    /// so a reordered set is not a change. Both sides are sorted for the
    /// comparison only — the store and the status keep the order they were
    /// given — and sorting also keeps duplicate entries from comparing
    /// equal.
    fn has_same_models(&self, current: Option<&InferenceProviderStatus>) -> bool {
        let current_models = current.and_then(|status| status.served_models.as_deref());
        let sorted = |models: &[String]| {
            let mut names = models.to_vec();
            names.sort_unstable();
            names
        };
        match (current_models, self.models.as_deref()) {
            (None, None) => true,
            (Some(current_names), Some(desired_names)) => sorted(current_names) == sorted(desired_names),
            _ => false,
        }
    }

    /// Whether `current` shows exactly this patch's failure reason.
    fn has_same_error(&self, current: Option<&InferenceProviderStatus>) -> bool {
        let current_error = current.and_then(|status| status.model_discovery_error.as_deref());
        current_error == self.failure_reason
    }
}

/// The discovery-owned status fields to apply: present fields only.
///
/// Server-side apply removes a field this manager owns when the applied
/// config omits it, which is how a cleared error or an expired set leaves
/// the status. Reconciler-owned fields are untouched.
fn discovery_status_fields(desired: &DiscoveryStatusPatch) -> serde_json::Value {
    let mut status = serde_json::Map::new();
    if let Some(reason) = desired.failure_reason {
        status.insert("modelDiscoveryError".to_owned(), serde_json::json!(reason));
    }
    if let Some(models) = &desired.models {
        status.insert("servedModels".to_owned(), serde_json::json!(models));
    }
    status.into()
}

/// Apply only the discovery-owned status fields.
async fn patch_discovery_status(
    api: &Api<InferenceProvider>,
    desired: &DiscoveryStatusPatch,
) -> Result<(), OperatorError> {
    let apply = serde_json::json!({
        "apiVersion": "grid.praxis.fast/v1alpha1",
        "kind": "InferenceProvider",
        "metadata": { "name": desired.name },
        "status": discovery_status_fields(desired)
    });
    api.patch_status(
        &desired.name,
        &PatchParams::apply(DISCOVERY_FIELD_MANAGER).force(),
        &Patch::Apply(apply),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Poll
// ---------------------------------------------------------------------------

/// Why one provider poll failed.
#[derive(Debug, thiserror::Error)]
enum PollError {
    /// The bearer token could not be read.
    #[error("credential unavailable: {0}")]
    Credential(String),

    /// TLS material could not be read or is invalid.
    #[error("TLS unavailable: {0}")]
    Tls(String),

    /// The source failed.
    #[error(transparent)]
    Source(#[from] DiscoveryError),
}

impl PollError {
    /// Bounded reason string for metrics labels.
    fn as_reason(&self) -> &'static str {
        match self {
            Self::Credential(_) => "credential",
            Self::Tls(_) => "tls",
            Self::Source(DiscoveryError::Config(_)) => "config",
            Self::Source(DiscoveryError::Transport(_)) => "unreachable",
            Self::Source(DiscoveryError::Timeout(_)) => "timeout",
            Self::Source(DiscoveryError::Status(_)) => "http_status",
            Self::Source(
                DiscoveryError::BodyTooLarge(_) | DiscoveryError::Malformed(_) | DiscoveryError::InvalidModels(_),
            ) => "invalid_response",
        }
    }
}

/// Query one provider's discovery source and record the outcome.
///
/// `None` when the provider has no name. Poll failures are logged and counted.
async fn poll(
    provider: &InferenceProvider,
    config: &ModelDiscoveryConfig,
    client: &Client,
    timeout: Duration,
) -> Option<ProviderPoll> {
    let name = provider.metadata.name.as_deref()?.to_owned();
    let result = match config {
        ModelDiscoveryConfig::OpenAiModels(openai) => query_openai(provider, openai, client, timeout).await,
    };

    let outcome = match result {
        Ok(models) => {
            metrics::record_model_discovery_success(&name);
            PollOutcome::Served(models)
        },
        Err(error) => {
            let reason = error.as_reason();
            metrics::record_model_discovery_failure(&name, reason);
            tracing::warn!(provider = %name, %error, "model discovery failed");
            PollOutcome::Failed(error)
        },
    };

    Some(ProviderPoll(outcome, name))
}

/// Build an [`OpenAiModels`] source and list its models.
async fn query_openai(
    provider: &InferenceProvider,
    openai: &OpenAiModelsSource,
    client: &Client,
    timeout: Duration,
) -> Result<ServedModels, PollError> {
    tokio::time::timeout(timeout, async {
        let source = openai_source(provider, openai, client, timeout).await?;
        Ok(source.served_models().await?)
    })
    .await
    .map_err(|_elapsed| PollError::Source(DiscoveryError::Timeout(timeout)))?
}

/// Build an [`OpenAiModels`] source, resolving credentials and TLS.
async fn openai_source(
    provider: &InferenceProvider,
    openai: &OpenAiModelsSource,
    client: &Client,
    timeout: Duration,
) -> Result<OpenAiModels, PollError> {
    let name = provider.metadata.name.as_deref().unwrap_or("?");
    let url = openai.effective_url(&provider.spec.endpoint);

    let token = match credentials::credential_plan_from_auth(provider.spec.auth.as_ref()) {
        Ok(CredentialPlan::Bearer(secret_ref)) => Some(
            Box::pin(KubernetesSecretResolver::new(client.clone()).resolve(&secret_ref))
                .await
                .map_err(|e| PollError::Credential(e.to_string()))?,
        ),
        Ok(CredentialPlan::Absent | CredentialPlan::Manual) => None,
        Err(e) => return Err(PollError::Credential(e.to_string())),
    };

    let ep_tls = openai.tls.as_ref().or(provider.spec.tls.as_ref());
    let client_tls = Box::pin(endpoint_tls::resolve_tls_config(ep_tls, Some(client), name))
        .await
        .map_err(|(_, message)| PollError::Tls(message))?;

    let uri = model_discovery::validated_uri(&url)?;
    let model_client = model_discovery::build_client(&uri, client_tls.as_ref(), timeout).await?;
    Ok(OpenAiModels::new(
        uri,
        token.as_ref(),
        client_tls.as_ref(),
        model_client,
        timeout,
    )?)
}

/// Build and query a model-discovery source backed by a local test server.
#[cfg(test)]
async fn query_openai_for_test(
    provider: &InferenceProvider,
    openai: &OpenAiModelsSource,
    client: &Client,
    timeout: Duration,
) -> Result<ServedModels, PollError> {
    let source = openai_source_for_test(provider, openai, client, timeout).await?;
    Ok(source.served_models().await?)
}

/// Build a test model-discovery source without shipping a loopback bypass.
#[cfg(test)]
async fn openai_source_for_test(
    provider: &InferenceProvider,
    openai: &OpenAiModelsSource,
    client: &Client,
    timeout: Duration,
) -> Result<OpenAiModels, PollError> {
    let name = provider.metadata.name.as_deref().unwrap_or("?");
    let url = openai.effective_url(&provider.spec.endpoint);

    let token = match credentials::credential_plan_from_auth(provider.spec.auth.as_ref()) {
        Ok(CredentialPlan::Bearer(secret_ref)) => Some(
            Box::pin(KubernetesSecretResolver::new(client.clone()).resolve(&secret_ref))
                .await
                .map_err(|e| PollError::Credential(e.to_string()))?,
        ),
        Ok(CredentialPlan::Absent | CredentialPlan::Manual) => None,
        Err(e) => return Err(PollError::Credential(e.to_string())),
    };

    let ep_tls = openai.tls.as_ref().or(provider.spec.tls.as_ref());
    let client_tls = Box::pin(endpoint_tls::resolve_tls_config(ep_tls, Some(client), name))
        .await
        .map_err(|(_, message)| PollError::Tls(message))?;
    Ok(model_discovery::new_for_test(&url, token.as_ref(), client_tls.as_ref(), timeout).await?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::model_discovery::ServedModelsError;

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn success_replaces_set() {
        let store = ServedModelStore::new();

        store.refresh(round(&[("p", Some(&["old"]))]), Instant::now(), TTL);
        store.refresh(round(&[("p", Some(&["b", "a"]))]), Instant::now(), TTL);

        assert_eq!(
            names(&store, "p"),
            Some(owned(&["a", "b"])),
            "success should replace set"
        );
    }

    #[test]
    fn empty_success_is_held() {
        let store = ServedModelStore::new();

        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), TTL);
        store.refresh(round(&[("p", Some(&[]))]), Instant::now(), TTL);

        assert_eq!(names(&store, "p"), Some(Vec::new()), "empty success should be held");
    }

    #[test]
    fn failure_keeps_last_good_set() {
        let store = ServedModelStore::new();

        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), TTL);
        store.refresh(round(&[("p", None)]), Instant::now(), TTL);

        assert_eq!(names(&store, "p"), Some(owned(&["a"])), "failure should keep set");
    }

    #[test]
    fn unrenewed_set_expires() {
        let store = ServedModelStore::new();

        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), Duration::ZERO);

        assert_eq!(names(&store, "p"), None, "expired set should not be served");
    }

    #[test]
    fn unpolled_provider_is_dropped() {
        let store = ServedModelStore::new();

        store.refresh(round(&[("p", Some(&["a"])), ("q", Some(&["b"]))]), Instant::now(), TTL);
        store.refresh(round(&[("q", None)]), Instant::now(), TTL);

        assert_eq!(names(&store, "p"), None, "unconfigured provider should be dropped");
        assert_eq!(
            names(&store, "q"),
            Some(owned(&["b"])),
            "failed provider should be kept"
        );
    }

    #[test]
    fn failures_map_to_reasons() {
        assert_eq!(
            PollError::Credential(String::new()).as_reason(),
            "credential",
            "credential"
        );
        assert_eq!(
            PollError::from(DiscoveryError::Status(http::StatusCode::UNAUTHORIZED)).as_reason(),
            "http_status",
            "status"
        );
        assert_eq!(
            PollError::from(DiscoveryError::InvalidModels(ServedModelsError::TooMany)).as_reason(),
            "invalid_response",
            "invalid models"
        );
    }

    #[test]
    fn failure_sets_reason_and_skips_unchanged_status() {
        let store = ServedModelStore::new();
        let provider_name = "provider-a";
        let provider_without_status = test_provider(provider_name, None);
        let provider_with_error = test_provider(provider_name, Some("credential"));
        let failed = vec![ProviderPollStatus {
            name: provider_name.to_owned(),
            failure_reason: Some("credential"),
        }];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider_without_status, &store, &failed),
            Some(DiscoveryStatusPatch {
                name: provider_name.to_owned(),
                failure_reason: Some("credential"),
                models: None,
            }),
            "a failed poll should set its reason"
        );
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider_with_error, &store, &failed),
            None,
            "an unchanged error should not be patched"
        );
    }

    #[test]
    fn success_or_disabled_discovery_clears_a_previous_error() {
        let store = ServedModelStore::new();
        let provider_name = "provider-a";
        let provider_with_error = test_provider(provider_name, Some("credential"));
        let succeeded = vec![ProviderPollStatus {
            name: provider_name.to_owned(),
            failure_reason: None,
        }];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider_with_error, &store, &succeeded),
            Some(DiscoveryStatusPatch {
                name: provider_name.to_owned(),
                failure_reason: None,
                models: None,
            }),
            "a successful poll should clear the previous error"
        );
        let polled = &[];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider_with_error, &store, polled),
            Some(DiscoveryStatusPatch {
                name: provider_name.to_owned(),
                failure_reason: None,
                models: None,
            }),
            "removing model discovery should clear the previous error"
        );
    }

    #[test]
    fn success_writes_the_served_set() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["b", "a"]))]), Instant::now(), TTL);

        let provider = &discovery_provider("p", &serde_json::json!({}));
        let polled = &[];
        let patch = DiscoveryStatusPatch::for_provider(provider, &store, polled);

        assert_eq!(
            patch,
            Some(DiscoveryStatusPatch {
                name: "p".to_owned(),
                failure_reason: None,
                models: Some(owned(&["b", "a"])),
            }),
            "a changed set should be written as polled"
        );
    }

    #[test]
    fn an_empty_set_is_written_not_cleared() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&[]))]), Instant::now(), TTL);

        let provider = &discovery_provider("p", &serde_json::json!({}));
        let polled = &[];
        let patch = DiscoveryStatusPatch::for_provider(provider, &store, polled);

        assert_eq!(
            patch.map(|desired| desired.models),
            Some(Some(Vec::new())),
            "an empty discovered set is present, distinct from absence"
        );
    }

    #[test]
    fn unchanged_status_is_not_patched() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), TTL);

        let provider = discovery_provider("p", &serde_json::json!({ "servedModels": ["a"] }));

        let polled = &[];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, polled),
            None,
            "an unchanged set should not be patched"
        );
    }

    #[test]
    fn a_reordered_set_is_not_a_change() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["a", "b"]))]), Instant::now(), TTL);

        let provider = discovery_provider("p", &serde_json::json!({ "servedModels": ["b", "a"] }));

        let polled = &[];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, polled),
            None,
            "response order is not part of the set"
        );
    }

    #[test]
    fn a_substituted_model_is_a_change() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["a", "b"]))]), Instant::now(), TTL);

        let provider = discovery_provider("p", &serde_json::json!({ "servedModels": ["a", "c"] }));

        let polled = &[];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, polled),
            Some(DiscoveryStatusPatch {
                name: "p".to_owned(),
                failure_reason: None,
                models: Some(owned(&["a", "b"])),
            }),
            "a substituted model must be written"
        );
    }

    #[test]
    fn failure_keeps_the_held_set_in_status() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), TTL);
        store.refresh(round(&[("p", None)]), Instant::now(), TTL);

        let provider = discovery_provider("p", &serde_json::json!({ "servedModels": ["a"] }));
        let failed = vec![ProviderPollStatus {
            name: "p".to_owned(),
            failure_reason: Some("unreachable"),
        }];

        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, &failed),
            Some(DiscoveryStatusPatch {
                name: "p".to_owned(),
                failure_reason: Some("unreachable"),
                models: Some(owned(&["a"])),
            }),
            "a failed poll sets its reason and keeps the held set"
        );
    }

    #[test]
    fn expired_set_is_cleared_from_status() {
        let store = ServedModelStore::new();
        store.refresh(round(&[("p", Some(&["a"]))]), Instant::now(), Duration::ZERO);

        let provider = discovery_provider("p", &serde_json::json!({ "servedModels": ["a"] }));
        let failed = vec![ProviderPollStatus {
            name: "p".to_owned(),
            failure_reason: Some("unreachable"),
        }];

        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, &failed),
            Some(DiscoveryStatusPatch {
                name: "p".to_owned(),
                failure_reason: Some("unreachable"),
                models: None,
            }),
            "an expired set must leave the status: fail closed"
        );
    }

    #[test]
    fn removed_discovery_clears_the_served_set() {
        let store = ServedModelStore::new();
        let provider = test_provider_with_status("p", &serde_json::json!({ "servedModels": ["a"] }));

        let polled = &[];
        assert_eq!(
            DiscoveryStatusPatch::for_provider(&provider, &store, polled),
            Some(DiscoveryStatusPatch {
                name: "p".to_owned(),
                failure_reason: None,
                models: None,
            }),
            "disabling discovery must clear the served set"
        );
    }

    #[test]
    fn status_apply_carries_only_present_fields() {
        let with_both = DiscoveryStatusPatch {
            name: "p".to_owned(),
            failure_reason: Some("timeout"),
            models: Some(owned(&["a"])),
        };
        assert_eq!(
            discovery_status_fields(&with_both),
            serde_json::json!({ "modelDiscoveryError": "timeout", "servedModels": ["a"] })
        );

        let cleared = DiscoveryStatusPatch {
            name: "p".to_owned(),
            failure_reason: None,
            models: None,
        };
        assert_eq!(
            discovery_status_fields(&cleared),
            serde_json::json!({}),
            "omitted fields are removed by the apply"
        );
    }

    #[test]
    fn urls_are_joined_with_one_slash() {
        let url = |base: &str, path: &str| {
            OpenAiModelsSource {
                endpoint: Some(base.to_owned()),
                path: path.to_owned(),
                tls: None,
            }
            .effective_url("unused")
        };
        assert_eq!(url("http://h/", "/v1/models"), "http://h/v1/models", "both slashes");
        assert_eq!(url("http://h", "v1/models"), "http://h/v1/models", "no slashes");
        assert_eq!(url("http://h/api", "/v1/models"), "http://h/api/v1/models", "base path");
    }

    /// Build an OpenAI-compatible model-list response.
    fn model_list_response(models: &[&str]) -> Vec<u8> {
        let body = serde_json::json!({
            "data": models.iter().map(|model| serde_json::json!({"id": model})).collect::<Vec<_>>()
        })
        .to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// Start a TLS model-list endpoint signed by `ca`.
    async fn tls_model_discovery_endpoint(ca: &certs::CaCert, models: &[&str]) -> String {
        let server_cert =
            certs::generate_dns_cert(ca, "model-server", "localhost").unwrap_or_else(|_| std::process::abort());
        crate::resources::test_doubles::start_tls_http_server(
            &server_cert.cert_pem,
            &server_cert.key_pem,
            model_list_response(models),
        )
        .await
    }

    fn openai_source(
        endpoint: Option<&str>,
        tls: Option<crate::crd::inference_provider::EndpointTlsConfig>,
    ) -> OpenAiModelsSource {
        OpenAiModelsSource {
            endpoint: endpoint.map(str::to_owned),
            path: "/v1/models".to_owned(),
            tls,
        }
    }

    #[tokio::test]
    async fn model_discovery_inherits_shared_tls() {
        let ca = certs::generate_ca("shared-discovery-ca").unwrap_or_else(|_| std::process::abort());
        let endpoint = tls_model_discovery_endpoint(&ca, &["model-a", "model-b"]).await;
        let client =
            crate::resources::test_doubles::mock_kube_client_with_secrets(std::collections::HashMap::from([(
                "shared-ca",
                crate::resources::test_doubles::secret_with_key("ca.crt", ca.cert_pem.as_bytes()),
            )]));
        let mut provider = test_provider("provider-a", None);
        provider.spec.endpoint = endpoint;
        provider.spec.tls = Some(crate::resources::test_doubles::endpoint_tls_for_ca("shared-ca"));

        let models = query_openai_for_test(&provider, &openai_source(None, None), &client, Duration::from_secs(5))
            .await
            .unwrap_or_else(|_| std::process::abort())
            .into_names();

        assert_eq!(models, vec!["model-a", "model-b"]);
    }

    #[tokio::test]
    async fn model_discovery_override_takes_precedence_over_shared_tls() {
        let ca = certs::generate_ca("override-discovery-ca").unwrap_or_else(|_| std::process::abort());
        let endpoint = tls_model_discovery_endpoint(&ca, &["model-a"]).await;
        let client =
            crate::resources::test_doubles::mock_kube_client_with_secrets(std::collections::HashMap::from([(
                "override-ca",
                crate::resources::test_doubles::secret_with_key("ca.crt", ca.cert_pem.as_bytes()),
            )]));
        let mut provider = test_provider("provider-a", None);
        provider.spec.endpoint = "https://unused.invalid".to_owned();
        provider.spec.tls = Some(crate::resources::test_doubles::endpoint_tls_for_ca("missing-shared-ca"));

        let models = query_openai_for_test(
            &provider,
            &openai_source(
                Some(&endpoint),
                Some(crate::resources::test_doubles::endpoint_tls_for_ca("override-ca")),
            ),
            &client,
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_else(|_| std::process::abort())
        .into_names();

        assert_eq!(
            models,
            vec!["model-a"],
            "openai.tls should override shared provider TLS"
        );
    }

    #[tokio::test]
    async fn model_discovery_shared_tls_resolution_failure_is_reported() {
        let client = crate::resources::test_doubles::mock_kube_client_with_secrets(std::collections::HashMap::new());
        let mut provider = test_provider("provider-a", None);
        provider.spec.endpoint = "https://localhost:8443".to_owned();
        provider.spec.tls = Some(crate::resources::test_doubles::endpoint_tls_for_ca("missing-shared-ca"));

        let result =
            query_openai_for_test(&provider, &openai_source(None, None), &client, Duration::from_secs(5)).await;

        assert!(
            matches!(result, Err(PollError::Tls(_))),
            "invalid shared TLS material must fail the poll"
        );
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn test_provider(name: &str, discovery_error: Option<&str>) -> InferenceProvider {
        let status = discovery_error.map_or_else(
            || serde_json::json!({}),
            |error| serde_json::json!({ "modelDiscoveryError": error }),
        );
        provider_from_json(name, &status, false)
    }

    fn test_provider_with_status(name: &str, status: &serde_json::Value) -> InferenceProvider {
        provider_from_json(name, status, false)
    }

    fn discovery_provider(name: &str, status: &serde_json::Value) -> InferenceProvider {
        provider_from_json(name, status, true)
    }

    fn provider_from_json(name: &str, status: &serde_json::Value, discovery: bool) -> InferenceProvider {
        let mut spec = serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://provider",
            "models": [{ "name": "model-a" }]
        });
        if discovery && let Some(spec) = spec.as_object_mut() {
            spec.insert("modelDiscovery".to_owned(), serde_json::json!({ "openAiModels": {} }));
        }
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis.fast/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": name },
            "spec": spec,
            "status": status.clone()
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    fn round(entries: &[(&str, Option<&[&str]>)]) -> Vec<ProviderPoll> {
        entries
            .iter()
            .map(|&(provider, models)| {
                let outcome = match models {
                    Some(names) => PollOutcome::Served(
                        ServedModels::try_from_names(names.iter().map(|&name| name.to_owned()))
                            .unwrap_or_else(|_| std::process::abort()),
                    ),
                    None => PollOutcome::Failed(PollError::Credential(String::new())),
                };
                ProviderPoll(outcome, provider.to_owned())
            })
            .collect()
    }

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    fn names(store: &ServedModelStore, provider: &str) -> Option<Vec<String>> {
        store.models(provider).map(|models| {
            let mut names = models.to_vec();
            names.sort_unstable();
            names
        })
    }
}
