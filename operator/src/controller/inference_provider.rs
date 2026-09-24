//! [`InferenceProvider`] controller (OP-02).
//!
//! Reconciles [`InferenceProvider`] resources: validates referenced
//! [`GridNetwork`], resolves matching [`GridSite`]s via the site selector,
//! verifies API-provider credentials, and sets `status.phase`,
//! `status.matchingSites`, and `status.observedGeneration`.
//!
//! # Phase policy
//!
//! Static config checks run first and short-circuit on any failure.
//! Credential verification runs after static checks and before site matching.
//! The health probe result (from `ProbeOutcome`) is applied last, on top
//! of the site-matching phase.
//!
//! | Condition | Phase |
//! |-----------|-------|
//! | `spec.endpoint` is blank or whitespace | `Unavailable` |
//! | Any `spec.models[].name` is blank | `Unavailable` |
//! | `spec.auth` specifies an unsupported strategy | `Unavailable` |
//! | `auth.strategy = bearer_token` but `secretRef` is absent or invalid | `Unavailable` |
//! | `auth.secretRef` Secret does not exist in the cluster | `Unavailable` |
//! | `auth.secretRef` key missing from the Secret | `Unavailable` |
//! | `auth.secretRef` key value is not valid UTF-8 | `Unavailable` |
//! | `spec.gridNetworkRef` not found | `Unavailable` |
//! | Config valid, probe returns transport failure | `Unavailable` |
//! | Config valid, probe returns degraded response | `Degraded` |
//! | `healthCheck.tls` Secret missing, key absent, or material invalid | `Degraded` |
//! | `metricsConfig.tls` Secret missing, key absent, or material invalid | `Degraded` |
//! | Config valid, probe healthy or not run, no matching sites | `Pending` |
//! | Config valid, probe healthy or not run, ≥1 matching site | `Available` |
//!
//! `Degraded` is emitted by `phase_from_probe` when a health probe
//! returns a degraded response, or by the health check / metrics TLS
//! validation when Secret references cannot be resolved or PEM material
//! is invalid.
//!
//! # Watch / reconcile note
//!
//! This controller watches [`InferenceProvider`] resources.  Changes to
//! [`GridSite`]s or [`GridNetwork`]s do not trigger an [`InferenceProvider`]
//! reconcile.  Adding cross-resource watches is a follow-up task.
//!
//! # Site matching
//!
//! The controller lists all [`GridSite`]s whose `spec.gridNetworkRef` equals
//! the provider's `spec.gridNetworkRef`, then applies the provider's
//! `spec.siteSelector.matchLabels`.  An empty selector matches all sites in
//! the network.  Network filtering (by `spec.gridNetworkRef`) is the
//! controller's responsibility — `sites_matching_selector` itself does not
//! filter by network.
//!
//! [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
//! [`GridNetwork`]: crate::crd::grid_network::GridNetwork
//! [`GridSite`]: crate::crd::grid_site::GridSite

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::StreamExt as _;
use http_body_util::Empty;
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use kube::{
    Client,
    api::{Api, ListParams, Patch, PatchParams},
    runtime::{controller::Action, watcher},
};
use tracing::info;

use crate::{
    crd::{
        grid_network::GridNetwork,
        grid_site::GridSite,
        inference_provider::{
            HealthCheckConfig, InferenceProvider, InferenceProviderSpec, InferenceProviderStatus, ModelDiscoverySource,
            ModelDiscoveryStatus, ProviderPhase,
        },
    },
    error::OperatorError,
    resources::{credentials, model_discovery, provider_metrics},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Requeue interval after a successful reconciliation when no `healthCheck.interval` is set.
const REQUEUE_INTERVAL: Duration = Duration::from_secs(300);

/// Shorter requeue interval for providers with `metricsConfig.tls` or
/// `healthCheck.tls` configured.
///
/// Without a cluster-wide Secret watch, the operator detects TLS material
/// rotation (certificate renewal, CA rollover) by re-reconciling on this
/// bounded interval.  60 seconds balances rotation detection latency against
/// API server load.  When `healthCheck.interval` is also set, the effective
/// interval is `min(healthCheck.interval, TLS_REQUEUE_INTERVAL)`.
const TLS_REQUEUE_INTERVAL: Duration = Duration::from_secs(60);

/// Default probe timeout when `spec.healthCheck.timeout` is absent.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default health-check path when `spec.healthCheck.path` is absent.
const DEFAULT_HEALTH_PATH: &str = "/health";

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

/// Reconcile an [`InferenceProvider`] resource.
///
/// # Errors
///
/// Returns [`OperatorError`] on Kubernetes API errors.
///
/// [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
pub async fn reconcile(provider: Arc<InferenceProvider>, client: Arc<Client>) -> Result<Action, OperatorError> {
    let name = provider
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| std::process::abort());

    info!(name, "reconciling InferenceProvider");

    let (phase, matching_sites, reason) = Box::pin(resolve_phase_and_sites(&provider, &client)).await?;
    let generation = provider.metadata.generation.unwrap_or(0);
    update_status(&provider, &client, phase, matching_sites, generation, reason).await?;

    Ok(Action::requeue(requeue_interval_for_provider(&provider.spec)))
}

/// Error policy for the [`InferenceProvider`] controller.
///
/// [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
pub fn error_policy(_provider: Arc<InferenceProvider>, error: &OperatorError, _ctx: Arc<Client>) -> Action {
    tracing::error!(%error, "InferenceProvider reconciliation failed");
    Action::requeue(Duration::from_secs(30))
}

// ---------------------------------------------------------------------------
// Phase resolution
// ---------------------------------------------------------------------------

/// Validate the static configuration of a provider (no Kubernetes API calls).
///
/// Returns `Some(reason)` if the provider has a configuration error that
/// immediately maps to [`ProviderPhase::Unavailable`], or `None` if static
/// validation passes.
///
/// Checked invariants:
/// - `spec.endpoint` is non-blank and non-whitespace.
/// - All `spec.models[].name` values are non-blank.
///
/// The `gridNetworkRef` existence check is not included here because it
/// requires a Kubernetes API call.
pub(crate) fn validate_provider_config(provider: &InferenceProvider) -> Option<&'static str> {
    if provider.spec.endpoint.trim().is_empty() {
        return Some("blank endpoint");
    }
    for model in &provider.spec.models {
        if model.name.trim().is_empty() {
            return Some("blank model name");
        }
    }
    None
}

/// The outcome of a health probe against an [`InferenceProvider`] endpoint.
///
/// Pass a [`ProbeOutcome`] to [`phase_from_probe`] to merge it with the
/// site-matching phase.  When `spec.healthCheck` is configured, the
/// reconcile loop runs a live HTTP probe via `probe_endpoint`; when
/// absent, [`ProbeOutcome::NotProbed`] preserves the site-matching phase.
///
/// [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    /// The endpoint responded successfully (e.g. HTTP 200).
    Healthy,

    /// The endpoint responded but signalled a degraded state (e.g. HTTP 5xx,
    /// or a valid response indicating reduced capacity).
    Degraded,

    /// The endpoint was unreachable: transport failure, connection refused,
    /// or DNS resolution error.
    Unavailable,

    /// No probe was attempted this reconcile cycle.
    ///
    /// Preserves the site-matching phase unchanged — equivalent to the
    /// pre-OP-05 behaviour.
    NotProbed,
}

impl ProbeOutcome {
    /// Derive a [`ProbeOutcome`] from an HTTP status code returned by a health probe.
    ///
    /// A 2xx status indicates the endpoint is healthy.  Any other status —
    /// redirects, client errors, server errors — indicates the endpoint is
    /// reachable but in a degraded state.
    ///
    /// Transport failures (connection refused, timeout, DNS error) are not
    /// representable as an HTTP status code; construct
    /// [`ProbeOutcome::Unavailable`] directly in those cases.
    ///
    /// | Status range | Result |
    /// |---|---|
    /// | 200–299 | [`Healthy`] |
    /// | any other | [`Degraded`] |
    ///
    /// [`Healthy`]: ProbeOutcome::Healthy
    /// [`Degraded`]: ProbeOutcome::Degraded
    #[must_use]
    pub fn from_http_status(status: u16) -> Self {
        if (200..300).contains(&status) {
            Self::Healthy
        } else {
            Self::Degraded
        }
    }
}

/// Apply a health [`ProbeOutcome`] on top of a site-matching phase.
///
/// The site-matching phase (from `phase_from_matching`) determines whether
/// the provider has any active sites.  The probe outcome can tighten or
/// override it:
///
/// | Probe outcome | Result |
/// |---------------|--------|
/// | [`Healthy`] | site-matching phase unchanged |
/// | [`NotProbed`] | site-matching phase unchanged |
/// | [`Degraded`] | [`ProviderPhase::Degraded`] |
/// | [`Unavailable`] | [`ProviderPhase::Unavailable`] |
///
/// Static config validation (`validate_provider_config`) runs **before**
/// this function and short-circuits on failure.  This function is only
/// called when static validation has already passed.
///
/// [`Healthy`]: ProbeOutcome::Healthy
/// [`NotProbed`]: ProbeOutcome::NotProbed
/// [`Degraded`]: ProbeOutcome::Degraded
/// [`Unavailable`]: ProbeOutcome::Unavailable
pub fn phase_from_probe(outcome: ProbeOutcome, site_phase: ProviderPhase) -> ProviderPhase {
    match outcome {
        ProbeOutcome::Healthy | ProbeOutcome::NotProbed => site_phase,
        ProbeOutcome::Degraded => ProviderPhase::Degraded,
        ProbeOutcome::Unavailable => ProviderPhase::Unavailable,
    }
}

/// Compute the provider phase from site matching results.
///
/// Returns [`ProviderPhase::Pending`] when no sites match, and
/// [`ProviderPhase::Available`] when at least one site matches.
///
/// This function never returns [`ProviderPhase::Degraded`].
/// `Degraded` is only reachable via [`phase_from_probe`] when a health
/// probe returns a degraded response.
pub(crate) fn phase_from_matching(matching: &[String]) -> ProviderPhase {
    if matching.is_empty() {
        ProviderPhase::Pending
    } else {
        ProviderPhase::Available
    }
}

// ---------------------------------------------------------------------------
// Health probe helpers
// ---------------------------------------------------------------------------

/// Build the URL to probe for a provider's health check.
///
/// Returns `None` when no [`HealthCheckConfig`] is present — the provider
/// will not be probed and [`ProbeOutcome::NotProbed`] is used instead.
///
/// When health check is configured:
/// - `healthCheck.endpoint` overrides `spec.endpoint` as the base URL when set.
/// - `path` defaults to `"/health"` when absent from the config.
/// - The endpoint's trailing slash is stripped before appending the path.
///
/// A blank `healthCheck.endpoint` is passed through as-is; [`probe_endpoint`]
/// will reject the resulting URL and return [`ProbeOutcome::Unavailable`],
/// surfacing the misconfiguration instead of silently skipping the probe.
///
/// This helper only constructs the URL.  Scheme support and TLS are handled
/// by [`probe_endpoint`].
///
/// [`HealthCheckConfig`]: crate::crd::inference_provider::HealthCheckConfig
pub(crate) fn probe_url_for_provider(spec: &InferenceProviderSpec) -> Option<String> {
    let hc = spec.health_check.as_ref()?;
    let path = hc.path.as_deref().unwrap_or(DEFAULT_HEALTH_PATH);
    let base = hc.endpoint.as_deref().unwrap_or(&spec.endpoint);
    let endpoint = base.trim_end_matches('/');
    let separator = if path.starts_with('/') { "" } else { "/" };
    Some(format!("{endpoint}{separator}{path}"))
}

/// Derive the probe timeout from [`HealthCheckConfig`].
///
/// Parses `spec.healthCheck.timeout` as `"<n>s"` (seconds) or
/// `"<n>ms"` (milliseconds).  Returns [`DEFAULT_PROBE_TIMEOUT`] (5s)
/// when the field is absent, `None`, or unparseable.
///
/// [`HealthCheckConfig`]: crate::crd::inference_provider::HealthCheckConfig
pub(crate) fn parse_probe_timeout(hc: Option<&HealthCheckConfig>) -> Duration {
    hc.and_then(|h| h.timeout.as_deref())
        .and_then(parse_duration_str)
        .unwrap_or(DEFAULT_PROBE_TIMEOUT)
}

/// Parse a human-readable duration string into a [`Duration`].
///
/// Accepted suffixes:
/// - `"ms"` → milliseconds
/// - `"s"` → seconds
///
/// Returns `None` for any other format.
fn parse_duration_str(s: &str) -> Option<Duration> {
    if let Some(n) = s.strip_suffix("ms") {
        n.trim().parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(n) = s.strip_suffix('s') {
        n.trim().parse::<u64>().ok().map(Duration::from_secs)
    } else {
        None
    }
}

/// Derive the reconcile requeue interval for an [`InferenceProvider`].
///
/// When `spec.healthCheck.interval` is configured and parseable, the
/// provider is requeued after that duration so that health probes run
/// at approximately the requested cadence.  When TLS is configured
/// (`metricsConfig.tls` or `healthCheck.tls`), the effective interval
/// is capped at [`TLS_REQUEUE_INTERVAL`] (60s) so the operator detects
/// certificate rotation without a cluster-wide Secret watch.  When no
/// interval is configured, falls back to [`TLS_REQUEUE_INTERVAL`] if
/// TLS is present, or [`REQUEUE_INTERVAL`] (300s) otherwise.
///
/// The interval controls **reconcile frequency**, not a separate timer
/// loop.  The probe runs at the start of each reconcile, so the actual
/// check cadence equals the requeue interval plus reconcile processing
/// time.  `healthCheck.timeout` does not affect the requeue interval;
/// the two fields are orthogonal.
///
/// [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
pub(crate) fn requeue_interval_for_provider(spec: &InferenceProviderSpec) -> Duration {
    let configured_interval = spec
        .health_check
        .as_ref()
        .and_then(|hc| hc.interval.as_deref())
        .and_then(parse_duration_str);

    let has_tls = spec.metrics_config.as_ref().is_some_and(|mc| mc.tls.is_some())
        || spec.health_check.as_ref().is_some_and(|hc| hc.tls.is_some());

    match (configured_interval, has_tls) {
        (Some(interval), true) => {
            let capped = interval.min(TLS_REQUEUE_INTERVAL);
            if capped < interval {
                tracing::info!(
                    configured = ?interval,
                    capped = ?capped,
                    "healthCheck.interval exceeds TLS requeue bound; capping to ensure timely certificate rotation detection"
                );
            }
            capped
        },
        (Some(interval), false) => interval,
        (None, true) => TLS_REQUEUE_INTERVAL,
        (None, false) => REQUEUE_INTERVAL,
    }
}

/// A periodic, bounded poller for discovery-enabled providers.
pub struct ModelDiscoveryPoller {
    /// Kubernetes client for source watches, credentials, and status writes.
    client: Client,
    /// Signal used to cancel an in-flight round.
    shutdown: crate::shutdown::Shutdown,
    /// Complete provider snapshot from the Kubernetes watch.
    providers: BTreeMap<String, InferenceProvider>,
    /// Replacement snapshot being built during watch initialization.
    initializing: Option<BTreeMap<String, InferenceProvider>>,
    /// Local attempt times cover status watch lag between rounds.
    last_started: BTreeMap<String, (i64, Instant)>,
    /// Maximum number of providers polled concurrently.
    concurrency: usize,
}

impl ModelDiscoveryPoller {
    /// Build a poller with the same bounded fan-out as the peer poller.
    #[must_use]
    pub fn new(client: Client, shutdown: crate::shutdown::Shutdown) -> Self {
        Self {
            client,
            shutdown,
            providers: BTreeMap::new(),
            initializing: None,
            last_started: BTreeMap::new(),
            concurrency: 8,
        }
    }

    /// Watch providers and poll due sources until shutdown.
    ///
    /// # Errors
    ///
    /// Watch and status errors are logged and retried. An unexpectedly closed
    /// provider watch returns an error; shutdown returns successfully.
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let api: Api<InferenceProvider> = Api::all(self.client.clone());
        let mut watch = watcher(api, watcher::Config::default()).boxed();
        loop {
            tokio::select! {
                biased;
                () = self.shutdown.triggered() => return Ok(()),
                event = watch.next() => match event {
                    Some(Ok(event)) => self.apply_watch_event(event),
                    Some(Err(error)) => tracing::warn!(%error, "model discovery: provider watch failed"),
                    None => return Err("model discovery provider watch closed".into()),
                },
                _ = ticker.tick() => {
                    let shutdown = self.shutdown.clone();
                    tokio::select! {
                        biased;
                        () = shutdown.triggered() => return Ok(()),
                        () = self.poll_once() => {},
                    }
                },
            }
        }
    }

    /// Poll each due source once, with bounded concurrency.
    async fn poll_once(&mut self) {
        let polls = self.take_due().into_iter().map(|provider| {
            let poller = &*self;
            async move { poller.poll_and_record_models(&provider).await }
        });
        futures::stream::iter(polls)
            .buffer_unordered(self.concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
    }

    /// Take a snapshot of due sources and remember each attempt before polling.
    fn take_due(&mut self) -> Vec<InferenceProvider> {
        if self.initializing.is_some() {
            return Vec::new();
        }
        let now = Instant::now();
        let due: Vec<InferenceProvider> = self
            .providers
            .values()
            .filter(|provider| self.poll_due(provider))
            .cloned()
            .collect();
        for provider in &due {
            if let Some(name) = provider.metadata.name.as_ref() {
                self.last_started
                    .insert(name.clone(), (provider.metadata.generation.unwrap_or(0), now));
            }
        }
        due
    }

    /// Check status and local attempt time before scheduling a provider.
    fn poll_due(&self, provider: &InferenceProvider) -> bool {
        let Some(name) = provider.metadata.name.as_deref() else {
            return false;
        };
        let Some(config) = provider.spec.model_discovery.as_ref() else {
            return false;
        };
        let generation = provider.metadata.generation.unwrap_or(0);
        let interval = Duration::from_secs(u64::from(config.effective_interval_seconds()));
        let status_recent = provider
            .status
            .as_ref()
            .and_then(|status| status.model_discovery.as_ref())
            .filter(|status| status.observed_generation == generation)
            .and_then(|status| status.last_attempt_time.as_deref())
            .and_then(|value| time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok())
            .is_some_and(|attempt| {
                let elapsed = time::OffsetDateTime::now_utc() - attempt;
                elapsed.is_positive()
                    && elapsed < time::Duration::seconds(i64::from(config.effective_interval_seconds()))
            });
        if status_recent {
            return false;
        }
        match self.last_started.get(name) {
            Some((seen_generation, started)) if *seen_generation == generation => started.elapsed() >= interval,
            _ => true,
        }
    }

    /// Apply a provider event, replacing the snapshot after initial sync.
    fn apply_watch_event(&mut self, event: watcher::Event<InferenceProvider>) {
        match event {
            watcher::Event::Init => self.initializing = Some(BTreeMap::new()),
            watcher::Event::InitApply(provider) => {
                if let Some(name) = provider.metadata.name.clone()
                    && let Some(pending) = self.initializing.as_mut()
                {
                    pending.insert(name, provider);
                }
            },
            watcher::Event::InitDone => {
                if let Some(pending) = self.initializing.take() {
                    self.providers = pending;
                    self.last_started.retain(|name, _| self.providers.contains_key(name));
                }
            },
            watcher::Event::Apply(provider) => {
                if let Some(name) = provider.metadata.name.clone() {
                    self.providers.insert(name, provider);
                }
            },
            watcher::Event::Delete(provider) => {
                if let Some(name) = provider.metadata.name.as_deref() {
                    self.providers.remove(name);
                    self.last_started.remove(name);
                }
            },
        }
    }

    /// Poll one provider and update only its discovery status field.
    async fn poll_and_record_models(&self, provider: &InferenceProvider) {
        let Some(name) = provider.metadata.name.as_deref() else {
            return;
        };
        let Some(config) = provider.spec.model_discovery.as_ref() else {
            return;
        };
        let previous = provider
            .status
            .as_ref()
            .and_then(|status| status.model_discovery.as_ref());
        let timeout = Duration::from_secs(u64::from(config.timeout_seconds.get()));
        let observation = match config.source {
            ModelDiscoverySource::OpenAiModels => {
                tokio::time::timeout(timeout, Box::pin(self.poll_open_ai_models(provider)))
                    .await
                    .unwrap_or(Err("Timeout"))
            },
        };
        let discovery = Self::status_after_poll(previous, provider.metadata.generation.unwrap_or(0), observation);
        let patch = serde_json::json!({
            "metadata": { "resourceVersion": provider.metadata.resource_version },
            "status": { "modelDiscovery": discovery }
        });
        let api: Api<InferenceProvider> = Api::all(self.client.clone());
        if let Err(error) = api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(patch))
            .await
        {
            tracing::warn!(name, %error, "model discovery: status update failed");
        }
    }

    /// Run one OpenAI-compatible model-list poll with the provider's auth material.
    async fn poll_open_ai_models(&self, provider: &InferenceProvider) -> Result<Vec<String>, &'static str> {
        use credentials::{CredentialPlan, CredentialResolver as _};

        let config = provider.spec.model_discovery.as_ref().ok_or("InvalidConfig")?;
        let uri = model_discovery::models_url(&provider.spec.endpoint, config)
            .map_err(model_discovery::DiscoveryFailure::as_str)?;
        let name = provider.metadata.name.as_deref().unwrap_or("?");
        let tls = crate::resources::endpoint_tls::resolve_tls_config(config.tls.as_ref(), Some(&self.client), name)
            .await
            .map_err(|_error| "TlsUnavailable")?;
        let plan = credentials::credential_plan_from_auth(provider.spec.auth.as_ref())
            .map_err(|_error| "CredentialUnavailable")?;
        let token = match plan {
            CredentialPlan::Bearer(reference) => Some(
                credentials::KubernetesSecretResolver::new(self.client.clone())
                    .resolve(&reference)
                    .await
                    .map_err(|_error| "CredentialUnavailable")?,
            ),
            CredentialPlan::Absent | CredentialPlan::Manual => None,
        };
        let timeout = Duration::from_secs(u64::from(config.timeout_seconds.get()));
        model_discovery::poll_models(
            uri,
            timeout,
            tls,
            token.as_ref().map(credentials::BearerToken::expose_secret),
        )
        .await
        .map_err(model_discovery::DiscoveryFailure::as_str)
    }

    /// Apply one poll result without treating a failure as an empty model set.
    fn status_after_poll(
        previous: Option<&ModelDiscoveryStatus>,
        generation: i64,
        result: Result<Vec<String>, &'static str>,
    ) -> ModelDiscoveryStatus {
        let mut status = previous
            .filter(|status| status.observed_generation == generation)
            .cloned()
            .unwrap_or_else(|| ModelDiscoveryStatus {
                observed_generation: generation,
                ..ModelDiscoveryStatus::default()
            });
        status.last_attempt_time = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
        match result {
            Ok(models) => {
                status.models = models;
                status.last_successful_time = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .ok();
                status.last_failure_reason = None;
            },
            Err(reason) => {
                status.last_failure_reason = Some(reason.to_owned());
            },
        }
        status
    }
}

/// Probe an `http://` or `https://` endpoint and return a [`ProbeOutcome`].
///
/// Uses a [`hyper_util`] HTTP/1.1 client.  When `tls_config` is `Some`, the
/// provided [`rustls::ClientConfig`] is used for server verification and
/// optional client certificate presentation (mTLS).  When `None`, native
/// root certificates are used (backward-compatible).
///
/// Only the response status code is inspected; the body is not buffered.
///
/// # Timeout
///
/// The entire request — including TLS handshake for `https://` — is wrapped
/// in `timeout`.  Exceeding the timeout returns [`ProbeOutcome::Unavailable`].
///
/// # Failure policy
///
/// | Outcome | [`ProbeOutcome`] |
/// |---------|-----------------|
/// | 2xx response | [`Healthy`] |
/// | non-2xx response | [`Degraded`] |
/// | Transport / TLS / DNS error | [`Unavailable`] |
/// | Timeout | [`Unavailable`] |
/// | Unsupported URL scheme (not `http` or `https`) | [`Unavailable`] |
/// | Unparseable URL | [`Unavailable`] |
/// | Native root certificate load failure (when no custom TLS) | [`Unavailable`] |
///
/// [`Healthy`]: ProbeOutcome::Healthy
/// [`Degraded`]: ProbeOutcome::Degraded
/// [`Unavailable`]: ProbeOutcome::Unavailable
#[expect(
    clippy::too_many_lines,
    reason = "URL parse + scheme check + TLS branch + client build + request: sequential steps"
)]
pub(crate) async fn probe_endpoint(
    url: &str,
    timeout: Duration,
    tls_config: Option<crate::resources::tls_backend::ClientTlsConfig>,
) -> ProbeOutcome {
    let Ok(uri) = url.parse::<http::Uri>() else {
        return ProbeOutcome::Unavailable;
    };

    // Only http and https are supported.
    match uri.scheme_str() {
        Some("http" | "https") => {},
        _ => return ProbeOutcome::Unavailable,
    }

    // Fail-closed: TLS config with a non-https URL is a misconfiguration.
    if tls_config.is_some() && uri.scheme_str() != Some("https") {
        tracing::warn!(
            url,
            "healthCheck.tls configured but endpoint uses http; probe will fail"
        );
        return ProbeOutcome::Unavailable;
    }

    let connector = if let Some(config) = &tls_config {
        // Custom TLS config: use the provided CA / client identity.
        match crate::metrics_scraper::build_custom_tls_connector(config) {
            Ok(connector) => connector,
            Err(_err) => return ProbeOutcome::Unavailable,
        }
    } else {
        // No custom TLS: use native root certificates.
        match crate::metrics_scraper::build_native_connector() {
            Ok(connector) => connector,
            Err(_err) => return ProbeOutcome::Unavailable,
        }
    };

    let client: HyperClient<_, Empty<Bytes>> = HyperClient::builder(TokioExecutor::new()).build(connector);

    let Ok(req) = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(Empty::<Bytes>::new())
    else {
        return ProbeOutcome::Unavailable;
    };

    let result = tokio::time::timeout(timeout, client.request(req)).await;

    match result {
        Err(_timeout) => ProbeOutcome::Unavailable,
        Ok(Err(_transport)) => ProbeOutcome::Unavailable,
        Ok(Ok(response)) => ProbeOutcome::from_http_status(response.status().as_u16()),
    }
}

/// Determine the provider phase, matching sites, and optional failure reason.
///
/// Returns `(ProviderPhase, sorted_matching_site_names, Option<status_reason>)`.
///
/// # Errors
///
/// Returns [`OperatorError`] on Kubernetes API failures.
#[expect(clippy::large_stack_frames, reason = "async future with kube API types")]
#[expect(
    clippy::too_many_lines,
    reason = "reconcile: static checks, credential verification, site matching, probe, metrics TLS, and phase merge"
)]
#[expect(
    clippy::cognitive_complexity,
    reason = "sequential reconcile steps with early returns and metrics TLS validation"
)]
async fn resolve_phase_and_sites(
    provider: &InferenceProvider,
    client: &Client,
) -> Result<(ProviderPhase, Vec<String>, Option<String>), OperatorError> {
    let name = provider.metadata.name.as_deref().unwrap_or("?");

    // Static validation: config errors map immediately to Unavailable.
    if let Some(config_error) = validate_provider_config(provider) {
        tracing::warn!(name, reason = config_error, "InferenceProvider config invalid");
        return Ok((ProviderPhase::Unavailable, Vec::new(), None));
    }

    // Credential plan validation: parse spec.auth without I/O.
    // Runs before network/site lookups so auth errors surface first.
    let plan = match credentials::credential_plan_from_auth(provider.spec.auth.as_ref()) {
        Err(e) => {
            let cr = credentials::credential_failure_reason_for_auth(provider.spec.auth.as_ref());
            tracing::warn!(name, error = %e, reason = cr.as_str(), "InferenceProvider auth config invalid");
            return Ok((ProviderPhase::Unavailable, Vec::new(), Some(cr.as_str().to_owned())));
        },
        Ok(plan) => plan,
    };

    // Credential accessibility: verify Secret exists, key present, value is UTF-8.
    // Kubernetes API errors propagate as Err (requeue); credential failures return
    // Ok(Some(reason)) and mark the provider Unavailable with status.reason.
    if let Some(cr) = credentials::verify_credential_accessible(client, &plan).await? {
        tracing::warn!(
            name,
            reason = cr.as_str(),
            "InferenceProvider credential Secret inaccessible"
        );
        return Ok((ProviderPhase::Unavailable, Vec::new(), Some(cr.as_str().to_owned())));
    }

    // Validate: referenced GridNetwork must exist.
    let network_ref = &provider.spec.grid_network_ref;
    let network_api: Api<GridNetwork> = Api::all(client.clone());
    if network_api.get_opt(network_ref).await?.is_none() {
        tracing::warn!(name, network = %network_ref, "referenced GridNetwork not found");
        return Ok((ProviderPhase::Unavailable, Vec::new(), None));
    }

    // Resolve matching sites.
    let sites = list_sites_for_network(client, network_ref).await?;
    let matching = sites_matching_selector(provider, &sites);
    let site_phase = phase_from_matching(&matching);

    // Resolve health check TLS config (if configured).  On failure, map
    // the error to a structured status reason and mark the provider Degraded.
    let health_tls_config = if let Some(hc) = &provider.spec.health_check
        && hc.tls.is_some()
    {
        match crate::resources::endpoint_tls::resolve_tls_config(hc.tls.as_ref(), Some(client), name).await {
            Ok(cfg) => cfg,
            Err((reason, e)) => {
                let reason_str = reason.as_status_reason("HealthCheck");
                tracing::warn!(
                    name,
                    reason = %reason_str,
                    error = %e,
                    "InferenceProvider health check TLS configuration invalid"
                );
                return Ok((ProviderPhase::Degraded, matching, Some(reason_str)));
            },
        }
    } else {
        None
    };

    // Run a live health probe when the spec opts in via `health_check`.
    // Providers without health_check config receive NotProbed, which
    // preserves the site-matching phase unchanged.
    // Warn if healthCheck.endpoint is present but blank — the probe will
    // fail with Unavailable, surfacing the misconfiguration.
    if let Some(hc) = &provider.spec.health_check
        && let Some(ep) = hc.endpoint.as_deref()
        && ep.trim().is_empty()
    {
        tracing::warn!(name, "healthCheck.endpoint is present but blank; probe will fail");
    }

    let probe_result = match probe_url_for_provider(&provider.spec) {
        Some(url) => {
            let timeout = parse_probe_timeout(provider.spec.health_check.as_ref());
            probe_endpoint(&url, timeout, health_tls_config).await
        },
        None => ProbeOutcome::NotProbed,
    };
    let phase = phase_from_probe(probe_result, site_phase);

    // Validate metrics TLS configuration.
    if phase == ProviderPhase::Available
        && let Some(mc) = &provider.spec.metrics_config
        && mc.tls.is_some()
        && let Some(tls_reason) = provider_metrics::verify_metrics_tls_accessible(client, mc.tls.as_ref()).await?
    {
        tracing::warn!(
            name,
            reason = %tls_reason,
            "InferenceProvider metrics TLS configuration invalid"
        );
        return Ok((ProviderPhase::Degraded, matching, Some(tls_reason)));
    }

    Ok((phase, matching, None))
}

/// List all [`GridSite`]s whose `spec.gridNetworkRef` matches `network_ref`.
///
/// Network filtering is applied here so that `sites_matching_selector`
/// only sees sites from the correct network.
///
/// [`GridSite`]: crate::crd::grid_site::GridSite
async fn list_sites_for_network(client: &Client, network_ref: &str) -> Result<Vec<GridSite>, OperatorError> {
    let api: Api<GridSite> = Api::all(client.clone());
    let all = api.list(&ListParams::default()).await?;
    Ok(all
        .items
        .into_iter()
        .filter(|s| s.spec.grid_network_ref == network_ref)
        .collect())
}

/// Apply `siteSelector.matchLabels` against the supplied sites.
///
/// An empty `matchLabels` matches all sites.  All configured key-value pairs
/// must match (AND semantics); extra labels on the site are ignored.
/// Returns a deterministically sorted list of matching site names.
///
/// Network filtering is the caller's responsibility — pass only sites that
/// already belong to the relevant network.
pub(crate) fn sites_matching_selector(provider: &InferenceProvider, sites: &[GridSite]) -> Vec<String> {
    let selector = &provider.spec.site_selector.match_labels;

    let mut names: Vec<String> = sites
        .iter()
        .filter(|site| {
            let site_labels = site.metadata.labels.as_ref();
            selector
                .iter()
                .all(|(k, v)| site_labels.is_some_and(|labels| labels.get(k).is_some_and(|sv| sv == v)))
        })
        .filter_map(|site| site.metadata.name.clone())
        .collect();

    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Status Update
// ---------------------------------------------------------------------------

/// Patch the [`InferenceProvider`] status subresource.
///
/// # Errors
///
/// Returns [`OperatorError`] on Kubernetes API errors.
///
/// [`InferenceProvider`]: crate::crd::inference_provider::InferenceProvider
#[expect(
    clippy::too_many_arguments,
    reason = "all parameters are distinct reconcile outputs; no logical grouping reduces them"
)]
#[expect(
    clippy::too_many_lines,
    reason = "status comparison and partial patch are one update"
)]
async fn update_status(
    provider: &InferenceProvider,
    client: &Client,
    phase: ProviderPhase,
    matching_sites: Vec<String>,
    observed_generation: i64,
    reason: Option<String>,
) -> Result<(), OperatorError> {
    let name = provider
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| std::process::abort());

    let api: Api<InferenceProvider> = Api::all(client.clone());
    let status = InferenceProviderStatus {
        matching_sites,
        observed_generation,
        phase,
        reason,
        model_discovery: provider.spec.model_discovery.as_ref().and_then(|_| {
            provider
                .status
                .as_ref()
                .and_then(|status| status.model_discovery.clone())
        }),
    };

    if !inference_provider_status_needs_update(provider.status.as_ref(), &status) {
        return Ok(());
    }

    let mut patch = serde_json::json!({
        "apiVersion": "grid.praxis-proxy.io/v1alpha1",
        "kind": "InferenceProvider",
        "status": {
            "matchingSites": status.matching_sites,
            "observedGeneration": status.observed_generation,
            "phase": status.phase,
            "reason": status.reason,
        }
    });
    if provider.spec.model_discovery.is_none()
        && let Some(fields) = patch.get_mut("status").and_then(serde_json::Value::as_object_mut)
    {
        fields.insert("modelDiscovery".to_owned(), serde_json::Value::Null);
    }

    api.patch_status(name, &PatchParams::default(), &Patch::Merge(patch))
        .await?;

    info!(name, "updated InferenceProvider status");
    Ok(())
}

/// Return whether the status subresource differs from the desired status.
fn inference_provider_status_needs_update(
    current: Option<&InferenceProviderStatus>,
    desired: &InferenceProviderStatus,
) -> bool {
    current != Some(desired)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn provider_status_update_is_skipped_when_semantically_unchanged() {
        let baseline = InferenceProviderStatus {
            matching_sites: vec!["site-a".to_owned()],
            observed_generation: 2,
            phase: ProviderPhase::Available,
            reason: None,
            model_discovery: None,
        };
        assert!(!inference_provider_status_needs_update(Some(&baseline), &baseline));

        let changed = InferenceProviderStatus {
            phase: ProviderPhase::Degraded,
            ..baseline.clone()
        };
        assert!(inference_provider_status_needs_update(Some(&baseline), &changed));
        assert!(inference_provider_status_needs_update(None, &baseline));
    }

    #[test]
    fn discovery_success_empty_and_failure_retention() {
        let first = ModelDiscoveryPoller::status_after_poll(None, 3, Ok(vec!["model-a".to_owned()]));
        assert_eq!(first.models, vec!["model-a"]);
        assert!(first.last_successful_time.is_some());
        assert!(first.last_failure_reason.is_none());

        let failed = ModelDiscoveryPoller::status_after_poll(Some(&first), 3, Err("HttpStatus"));
        assert_eq!(failed.models, first.models);
        assert_eq!(failed.last_successful_time, first.last_successful_time);
        assert_eq!(failed.last_failure_reason.as_deref(), Some("HttpStatus"));

        let empty = ModelDiscoveryPoller::status_after_poll(Some(&failed), 3, Ok(Vec::new()));
        assert!(empty.models.is_empty());
        assert!(empty.last_failure_reason.is_none());
        assert!(empty.last_successful_time.is_some());
    }

    #[test]
    fn discovery_spec_change_invalidates_last_good_observation() {
        let previous = ModelDiscoveryPoller::status_after_poll(None, 3, Ok(vec!["old-model".to_owned()]));
        let next = ModelDiscoveryPoller::status_after_poll(Some(&previous), 4, Err("HttpStatus"));
        assert!(next.models.is_empty());
        assert!(next.last_successful_time.is_none());
        assert_eq!(next.observed_generation, 4);
    }

    #[tokio::test]
    async fn discovery_status_watch_does_not_trigger_an_immediate_second_poll() {
        let mut provider = discovery_test_provider();
        let poller = test_model_poller();
        provider.status = Some(InferenceProviderStatus {
            matching_sites: Vec::new(),
            observed_generation: 3,
            phase: ProviderPhase::Available,
            reason: None,
            model_discovery: Some(ModelDiscoveryPoller::status_after_poll(None, 3, Err("HttpStatus"))),
        });
        assert!(!poller.poll_due(&provider));
        provider.metadata.generation = Some(4);
        assert!(poller.poll_due(&provider));
        provider.metadata.generation = Some(3);
        if let Some(status) = provider
            .status
            .as_mut()
            .and_then(|status| status.model_discovery.as_mut())
        {
            status.last_attempt_time = Some("2020-01-01T00:00:00Z".to_owned());
        }
        assert!(poller.poll_due(&provider));
    }

    #[tokio::test]
    async fn discovery_poller_selects_only_due_providers() {
        let mut provider = test_provider("backend", "net", &[]);
        let mut poller = test_model_poller();
        assert!(!poller.poll_due(&provider));
        provider = discovery_test_provider();
        assert!(poller.poll_due(&provider));
        poller.last_started.insert("backend".to_owned(), (3, Instant::now()));
        assert!(!poller.poll_due(&provider));
        provider.status = Some(InferenceProviderStatus {
            matching_sites: Vec::new(),
            observed_generation: 3,
            phase: ProviderPhase::Available,
            reason: None,
            model_discovery: Some(ModelDiscoveryPoller::status_after_poll(
                None,
                3,
                Ok(vec!["model-a".to_owned()]),
            )),
        });
        assert!(!poller.poll_due(&provider));
        provider.metadata.generation = Some(4);
        assert!(poller.poll_due(&provider));
    }

    #[tokio::test]
    async fn discovery_poller_replaces_and_updates_watched_sources() {
        let mut poller = test_model_poller();
        poller.apply_watch_event(watcher::Event::Apply(test_provider("old", "net", &[])));
        assert!(poller.providers.contains_key("old"));
        poller.apply_watch_event(watcher::Event::Init);
        poller.apply_watch_event(watcher::Event::InitApply(test_provider("new", "net", &[])));
        poller.apply_watch_event(watcher::Event::InitDone);
        assert!(!poller.providers.contains_key("old"));
        assert!(poller.providers.contains_key("new"));
        poller.apply_watch_event(watcher::Event::Delete(test_provider("new", "net", &[])));
        assert!(poller.providers.is_empty());
    }

    #[tokio::test]
    async fn discovery_poller_waits_for_a_complete_snapshot_and_avoids_repeat_rounds() {
        let mut poller = test_model_poller();
        poller.apply_watch_event(watcher::Event::Init);
        poller.apply_watch_event(watcher::Event::InitApply(discovery_test_provider()));
        assert!(poller.take_due().is_empty());
        poller.apply_watch_event(watcher::Event::InitDone);
        assert_eq!(poller.take_due().len(), 1);
        assert!(poller.take_due().is_empty());
    }

    #[test]
    fn discovery_interval_does_not_change_health_requeue() {
        let mut spec = make_spec_with_health_check_config("http://backend:8000", None);
        spec.model_discovery = Some(crate::crd::inference_provider::ModelDiscoveryConfig {
            source: ModelDiscoverySource::OpenAiModels,
            endpoint: None,
            interval_seconds: Some(std::num::NonZeroU32::new(20).unwrap_or_else(|| std::process::abort())),
            timeout_seconds: std::num::NonZeroU32::new(5).unwrap_or_else(|| std::process::abort()),
            tls: None,
        });
        assert_eq!(requeue_interval_for_provider(&spec), REQUEUE_INTERVAL);
        if let Some(config) = spec.model_discovery.as_mut() {
            config.interval_seconds = None;
        }
        assert_eq!(requeue_interval_for_provider(&spec), REQUEUE_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Test utilities
    // -----------------------------------------------------------------------

    fn test_model_poller() -> ModelDiscoveryPoller {
        let config = kube::Config::new("http://127.0.0.1:1".parse().unwrap_or_else(|_| std::process::abort()));
        let client = Client::try_from(config).unwrap_or_else(|_| std::process::abort());
        ModelDiscoveryPoller::new(client, crate::shutdown::Shutdown::never())
    }

    fn discovery_test_provider() -> InferenceProvider {
        let mut provider = test_provider("backend", "net", &[]);
        provider.spec.model_discovery = Some(crate::crd::inference_provider::ModelDiscoveryConfig {
            source: ModelDiscoverySource::OpenAiModels,
            endpoint: None,
            interval_seconds: None,
            timeout_seconds: std::num::NonZeroU32::new(5).unwrap_or_else(|| std::process::abort()),
            tls: None,
        });
        provider.metadata.generation = Some(3);
        provider
    }

    fn test_site(name: &str, network: &str) -> GridSite {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "GridSite",
            "metadata": { "name": name },
            "spec": { "gridNetworkRef": network }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    fn test_site_with_labels(name: &str, network: &str, labels: &[(&str, &str)]) -> GridSite {
        let labels_map: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "GridSite",
            "metadata": { "name": name, "labels": labels_map },
            "spec": { "gridNetworkRef": network }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    fn test_provider(name: &str, network: &str, models: &[&str]) -> InferenceProvider {
        let models_json: Vec<serde_json::Value> = models.iter().map(|m| serde_json::json!({ "name": m })).collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": name },
            "spec": {
                "gridNetworkRef": network,
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "http://localhost:8000",
                "models": models_json
            }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    fn test_provider_with_selector(name: &str, network: &str, selector: &[(&str, &str)]) -> InferenceProvider {
        let match_labels: serde_json::Map<String, serde_json::Value> = selector
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": name },
            "spec": {
                "gridNetworkRef": network,
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "http://localhost:8000",
                "models": [{"name": "model"}],
                "siteSelector": { "matchLabels": match_labels }
            }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    // -----------------------------------------------------------------------
    // resolve_phase_and_sites — integration tier: reconcile-path TLS
    // failure reasons through a mocked kube::Client (grid#58)
    //
    // The unit tier (endpoint_tls.rs, secret.rs) already exercises
    // resolve_tls_config/read_secret_bytes directly. These tests instead
    // drive the same scenario through resolve_phase_and_sites — the actual
    // function reconcile() calls — proving the SecretMissing/KeyMissing
    // distinction survives all the way to the (phase, status.reason) pair
    // reconcile() writes to the CR, not just to an intermediate type.
    // -----------------------------------------------------------------------

    use std::collections::HashMap;

    use k8s_openapi::{ByteString, api::core::v1::Secret};

    /// Build an HTTP 200 JSON response from any serializable value.
    fn json_ok(body: &impl serde::Serialize) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(200)
            .body(kube::client::Body::from(
                serde_json::to_vec(body).unwrap_or_else(|_| std::process::abort()),
            ))
            .unwrap_or_else(|_| std::process::abort())
    }

    /// Build an HTTP 404 Kubernetes `Status` response for a named resource.
    ///
    /// Must actually set the 404 status (not reuse [`json_ok`]'s 200) —
    /// `kube`'s client only maps a response onto `ApiError`/`get_opt: None`
    /// when the HTTP status itself is 404; a 200 body shaped like a `Status`
    /// object is instead treated as a malformed resource and surfaces as a
    /// deserialization error.
    fn json_not_found(resource_and_name: &str) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(404)
            .body(kube::client::Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": format!("{resource_and_name} not found"),
                    "reason": "NotFound",
                    "code": 404,
                }))
                .unwrap_or_else(|_| std::process::abort()),
            ))
            .unwrap_or_else(|_| std::process::abort())
    }

    /// A `kube::Client` that serves just enough of the Kubernetes API surface
    /// for `resolve_phase_and_sites` to reach its health-check TLS branch:
    /// a `GridNetwork` matching `provider.spec.gridNetworkRef`, an empty
    /// `GridSite` list, and the supplied CA Secrets.
    fn mock_kube_client_for_health_tls(
        grid_network_name: &'static str,
        secrets: HashMap<&'static str, Secret>,
    ) -> Client {
        let service = tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let secrets = secrets.clone();
            async move {
                let path = req.uri().path().to_owned();
                let name = path.rsplit('/').next().unwrap_or_default().to_owned();
                let response = if path.contains("/secrets/") {
                    secrets
                        .get(name.as_str())
                        .map_or_else(|| json_not_found(&format!("secrets {name:?}")), json_ok)
                } else if path.ends_with("/gridsites") {
                    json_ok(&serde_json::json!({
                        "apiVersion": "grid.praxis-proxy.io/v1alpha1",
                        "kind": "GridSiteList",
                        "items": [],
                    }))
                } else if path.contains("/gridnetworks/") && name == grid_network_name {
                    json_ok(&serde_json::json!({
                        "apiVersion": "grid.praxis-proxy.io/v1alpha1",
                        "kind": "GridNetwork",
                        "metadata": { "name": grid_network_name },
                        "spec": {},
                    }))
                } else {
                    json_not_found(&format!("gridnetworks {name:?}"))
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        Client::new(service, "default")
    }

    fn secret_with_key(key: &str, value: &[u8]) -> Secret {
        let mut data = BTreeMap::new();
        data.insert(key.to_owned(), ByteString(value.to_vec()));
        Secret {
            data: Some(data),
            ..Default::default()
        }
    }

    /// An otherwise-valid provider with `healthCheck.tls.caSecretRef` pointing
    /// at `ca_secret_name` in the `default` namespace.
    fn provider_with_health_check_tls(network: &str, ca_secret_name: &str) -> InferenceProvider {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "prov" },
            "spec": {
                "gridNetworkRef": network,
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "http://localhost:8000",
                "models": [{"name": "model"}],
                "healthCheck": {
                    "tls": {
                        "caSecretRef": { "name": ca_secret_name, "namespace": "default" }
                    }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    #[tokio::test]
    async fn resolve_phase_and_sites_health_check_key_absent_from_existing_secret_yields_degraded_key_missing() {
        let client = mock_kube_client_for_health_tls(
            "net-1",
            HashMap::from([("ca-secret", secret_with_key("wrong-key", b"ca-bytes"))]),
        );
        let provider = provider_with_health_check_tls("net-1", "ca-secret");

        let (phase, matching, reason) = resolve_phase_and_sites(&provider, &client)
            .await
            .expect("mocked API calls must not fail");

        assert_eq!(phase, ProviderPhase::Degraded);
        assert!(matching.is_empty(), "no GridSites exist in this fixture");
        assert_eq!(
            reason.as_deref(),
            Some("HealthCheckTlsKeyMissing"),
            "grid#58: end-to-end through resolve_phase_and_sites (the function reconcile() calls), a key \
             absent from an existing Secret's data must produce status.reason = HealthCheckTlsKeyMissing, \
             not HealthCheckTlsSecretMissing"
        );
    }

    #[tokio::test]
    async fn resolve_phase_and_sites_health_check_secret_absent_yields_degraded_secret_missing() {
        let client = mock_kube_client_for_health_tls("net-1", HashMap::new());
        let provider = provider_with_health_check_tls("net-1", "absent-secret");

        let (phase, _matching, reason) = resolve_phase_and_sites(&provider, &client)
            .await
            .expect("mocked API calls must not fail");

        assert_eq!(phase, ProviderPhase::Degraded);
        assert_eq!(reason.as_deref(), Some("HealthCheckTlsSecretMissing"));
    }

    // -----------------------------------------------------------------------
    // validate_provider_config — static validation (items 1-4)
    // -----------------------------------------------------------------------

    #[test]
    fn blank_endpoint_maps_to_unavailable() {
        // Item 1: blank endpoint
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "prov" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "",
                "models": [{"name": "model"}]
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let err = validate_provider_config(&provider);
        assert!(err.is_some(), "blank endpoint must fail static validation");
        assert!(
            err.unwrap_or_else(|| std::process::abort()).contains("endpoint"),
            "error must mention endpoint"
        );
    }

    #[test]
    fn whitespace_only_endpoint_maps_to_unavailable() {
        // Item 2: whitespace-only endpoint
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "prov" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "   ",
                "models": [{"name": "model"}]
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert!(
            validate_provider_config(&provider).is_some(),
            "whitespace-only endpoint must fail validation"
        );
    }

    #[test]
    fn blank_model_name_maps_to_unavailable() {
        // Item 3: blank model name
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "prov" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "http://localhost:8000",
                "models": [{"name": ""}]
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let err = validate_provider_config(&provider);
        assert!(err.is_some(), "blank model name must fail static validation");
        assert!(
            err.unwrap_or_else(|| std::process::abort()).contains("model"),
            "error must mention model"
        );
    }

    #[test]
    fn second_model_blank_maps_to_unavailable() {
        // Item 4: first model valid, second blank
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "prov" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "http://localhost:8000",
                "models": [{"name": "model-ok"}, {"name": ""}]
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert!(
            validate_provider_config(&provider).is_some(),
            "any blank model name must fail validation"
        );
    }

    #[test]
    fn valid_config_passes_static_validation() {
        // Items 1-4 all pass: good endpoint and all model names non-blank
        let provider = test_provider("prov", "net", &["model-a", "model-b"]);
        assert!(
            validate_provider_config(&provider).is_none(),
            "valid provider config must pass static validation"
        );
    }

    // Item 5: missing GridNetwork → Unavailable
    // Requires a Kubernetes API call (network_api.get_opt) and cannot be
    // unit-tested without a live cluster or a mock Kubernetes server.
    // Covered at the integration level; documented here for completeness.

    // -----------------------------------------------------------------------
    // phase_from_matching — pure phase logic (items 6-7, 12)
    // -----------------------------------------------------------------------

    #[test]
    fn no_matching_sites_yields_pending() {
        // Item 6: valid config, no matching sites → Pending
        let phase = phase_from_matching(&[]);
        assert_eq!(phase, ProviderPhase::Pending, "empty matching → Pending");
    }

    #[test]
    fn one_matching_site_yields_available() {
        // Item 7: valid config, ≥1 matching site → Available
        let phase = phase_from_matching(&["site-a".to_owned()]);
        assert_eq!(phase, ProviderPhase::Available, "one match → Available");
    }

    #[test]
    fn multiple_matching_sites_yields_available() {
        // Item 7 (multi-site): all non-empty slices → Available
        let phase = phase_from_matching(&["site-a".to_owned(), "site-b".to_owned()]);
        assert_eq!(phase, ProviderPhase::Available, "multiple matches → Available");
    }

    #[test]
    fn phase_from_matching_never_emits_degraded() {
        // phase_from_matching only returns Pending or Available; Degraded is
        // only reachable via phase_from_probe when a health probe returns a
        // degraded outcome.
        let empty_phase = phase_from_matching(&[]);
        let some_phase = phase_from_matching(&["site-x".to_owned()]);
        assert!(
            matches!(empty_phase, ProviderPhase::Pending),
            "empty matching must yield Pending"
        );
        assert!(
            matches!(some_phase, ProviderPhase::Available),
            "non-empty matching must yield Available"
        );
        assert_ne!(
            empty_phase,
            ProviderPhase::Degraded,
            "Degraded unreachable from phase_from_matching"
        );
        assert_ne!(
            some_phase,
            ProviderPhase::Degraded,
            "Degraded unreachable from phase_from_matching"
        );
    }

    // -----------------------------------------------------------------------
    // phase_from_probe — health decision function
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_probe_preserves_available() {
        let result = phase_from_probe(ProbeOutcome::Healthy, ProviderPhase::Available);
        assert_eq!(
            result,
            ProviderPhase::Available,
            "Healthy probe must preserve Available"
        );
    }

    #[test]
    fn healthy_probe_preserves_pending() {
        let result = phase_from_probe(ProbeOutcome::Healthy, ProviderPhase::Pending);
        assert_eq!(result, ProviderPhase::Pending, "Healthy probe must preserve Pending");
    }

    #[test]
    fn not_probed_preserves_available() {
        let result = phase_from_probe(ProbeOutcome::NotProbed, ProviderPhase::Available);
        assert_eq!(
            result,
            ProviderPhase::Available,
            "NotProbed must preserve Available (current default)"
        );
    }

    #[test]
    fn not_probed_preserves_pending() {
        let result = phase_from_probe(ProbeOutcome::NotProbed, ProviderPhase::Pending);
        assert_eq!(
            result,
            ProviderPhase::Pending,
            "NotProbed must preserve Pending (current default)"
        );
    }

    #[test]
    fn degraded_probe_overrides_available() {
        let result = phase_from_probe(ProbeOutcome::Degraded, ProviderPhase::Available);
        assert_eq!(
            result,
            ProviderPhase::Degraded,
            "Degraded probe must override Available"
        );
    }

    #[test]
    fn degraded_probe_overrides_pending() {
        let result = phase_from_probe(ProbeOutcome::Degraded, ProviderPhase::Pending);
        assert_eq!(result, ProviderPhase::Degraded, "Degraded probe must override Pending");
    }

    #[test]
    fn unavailable_probe_overrides_available() {
        let result = phase_from_probe(ProbeOutcome::Unavailable, ProviderPhase::Available);
        assert_eq!(
            result,
            ProviderPhase::Unavailable,
            "Unavailable probe must override Available"
        );
    }

    #[test]
    fn unavailable_probe_overrides_pending() {
        let result = phase_from_probe(ProbeOutcome::Unavailable, ProviderPhase::Pending);
        assert_eq!(
            result,
            ProviderPhase::Unavailable,
            "Unavailable probe must override Pending"
        );
    }

    #[test]
    fn degraded_is_reachable_via_phase_from_probe() {
        // Documents that Degraded IS now reachable from the controller, via
        // phase_from_probe — in contrast to phase_from_matching which cannot
        // emit it.
        let result = phase_from_probe(ProbeOutcome::Degraded, ProviderPhase::Available);
        assert_eq!(
            result,
            ProviderPhase::Degraded,
            "Degraded must be reachable via phase_from_probe"
        );
    }

    // -----------------------------------------------------------------------
    // ProbeOutcome::from_http_status — HTTP status code mapping
    // -----------------------------------------------------------------------

    #[test]
    fn http_200_yields_healthy() {
        assert_eq!(
            ProbeOutcome::from_http_status(200),
            ProbeOutcome::Healthy,
            "HTTP 200 must yield Healthy"
        );
    }

    #[test]
    fn http_204_yields_healthy() {
        assert_eq!(
            ProbeOutcome::from_http_status(204),
            ProbeOutcome::Healthy,
            "HTTP 204 No Content must yield Healthy"
        );
    }

    #[test]
    fn http_299_is_last_healthy_status() {
        assert_eq!(
            ProbeOutcome::from_http_status(299),
            ProbeOutcome::Healthy,
            "HTTP 299 must still be within the healthy range"
        );
    }

    #[test]
    fn http_300_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(300),
            ProbeOutcome::Degraded,
            "HTTP 300 (redirect) is outside 2xx range and must yield Degraded"
        );
    }

    #[test]
    fn http_400_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(400),
            ProbeOutcome::Degraded,
            "HTTP 400 must yield Degraded"
        );
    }

    #[test]
    fn http_429_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(429),
            ProbeOutcome::Degraded,
            "HTTP 429 Too Many Requests must yield Degraded"
        );
    }

    #[test]
    fn http_500_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(500),
            ProbeOutcome::Degraded,
            "HTTP 500 must yield Degraded"
        );
    }

    #[test]
    fn http_503_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(503),
            ProbeOutcome::Degraded,
            "HTTP 503 Service Unavailable must yield Degraded (reachable but degraded)"
        );
    }

    #[test]
    fn http_status_zero_yields_degraded() {
        assert_eq!(
            ProbeOutcome::from_http_status(0),
            ProbeOutcome::Degraded,
            "invalid status 0 must yield Degraded"
        );
    }

    #[test]
    fn http_2xx_boundary_is_inclusive_exclusive() {
        // 200 → Healthy, 299 → Healthy, 300 → Degraded
        assert_eq!(ProbeOutcome::from_http_status(200), ProbeOutcome::Healthy);
        assert_eq!(ProbeOutcome::from_http_status(299), ProbeOutcome::Healthy);
        assert_eq!(ProbeOutcome::from_http_status(300), ProbeOutcome::Degraded);
    }

    #[test]
    fn http_199_yields_degraded() {
        // 199 is below the 2xx range and must be treated as Degraded.
        assert_eq!(
            ProbeOutcome::from_http_status(199),
            ProbeOutcome::Degraded,
            "HTTP 199 is below 2xx range and must yield Degraded"
        );
    }

    #[test]
    fn static_config_failure_precedes_probe_result() {
        // Static config validation short-circuits before phase_from_probe is
        // called.  When validate_provider_config returns Some(_), the caller
        // returns Unavailable immediately — no probe outcome can rescue a
        // provider with an invalid config.
        //
        // Simulate the precedence: if static validation fails, we would
        // never reach phase_from_probe.  The test confirms both that
        // validate_provider_config catches the config error AND that
        // phase_from_probe does not participate in that path.
        let provider_with_blank_endpoint: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "bad" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "",
                "models": [{"name": "model"}]
            }
        }))
        .unwrap_or_else(|_| std::process::abort());

        let config_error = validate_provider_config(&provider_with_blank_endpoint);
        assert!(
            config_error.is_some(),
            "blank endpoint must fail static validation before any probe result applies"
        );
        // phase_from_probe is never called; this ensures it can never rescue
        // a provider with an invalid config.
    }

    // -----------------------------------------------------------------------
    // sites_matching_selector — selector matching (items 8-11)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_selector_matches_all_passed_sites() {
        // Item 8: empty selector matches all pre-filtered sites
        let provider = test_provider("prov", "net", &["model"]);
        let sites = vec![test_site("site-a", "net"), test_site("site-b", "net")];
        let matching = sites_matching_selector(&provider, &sites);
        assert_eq!(
            matching,
            vec!["site-a", "site-b"],
            "empty selector must match all pre-filtered sites"
        );
    }

    #[test]
    fn label_selector_matches_only_matching_labels() {
        // Item 9: label selector matches only labeled sites
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu")]);
        let sites = vec![
            test_site_with_labels("gpu-site", "net", &[("hw", "gpu")]),
            test_site_with_labels("cpu-site", "net", &[("hw", "cpu")]),
        ];
        let matching = sites_matching_selector(&provider, &sites);
        assert_eq!(matching, vec!["gpu-site"], "only gpu-site should match");
    }

    #[test]
    fn matching_sites_are_sorted_deterministically() {
        // Item 10: deterministic alphabetical sort
        let provider = test_provider("prov", "net", &["model"]);
        let sites = vec![
            test_site("zebra-site", "net"),
            test_site("alpha-site", "net"),
            test_site("mango-site", "net"),
        ];
        let matching = sites_matching_selector(&provider, &sites);
        assert_eq!(
            matching,
            vec!["alpha-site", "mango-site", "zebra-site"],
            "matching sites must be sorted alphabetically"
        );
    }

    #[test]
    fn sites_from_other_network_match_empty_selector() {
        // Item 11 (contract doc): sites_matching_selector does NOT filter by
        // network — that is the controller's responsibility via
        // list_sites_for_network.  An empty selector will match any site
        // passed in, regardless of network.
        let provider = test_provider("prov", "net", &["model"]);
        let sites = vec![test_site("site-other", "other-net")];
        let matching = sites_matching_selector(&provider, &sites);
        assert_eq!(
            matching,
            vec!["site-other"],
            "empty selector matches any site; network filtering is the controller's responsibility"
        );
    }

    #[test]
    fn no_matching_sites_returns_empty() {
        // Item 9 (negative): label selector, no sites match → empty
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu")]);
        let sites = vec![test_site_with_labels("cpu-site", "net", &[("hw", "cpu")])];
        let matching = sites_matching_selector(&provider, &sites);
        assert!(matching.is_empty(), "no matching sites should return empty");
    }

    #[test]
    fn multi_key_selector_requires_all_keys_to_match() {
        // Item 9 (AND semantics): all selector keys must match
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu"), ("region", "us-east")]);
        // Site with both keys → matches
        let both = test_site_with_labels(
            "full-match",
            "net",
            &[("hw", "gpu"), ("region", "us-east"), ("extra", "ignored")],
        );
        // Site with only one key → no match
        let partial = test_site_with_labels("partial", "net", &[("hw", "gpu")]);
        let sites = vec![both, partial];
        let matching = sites_matching_selector(&provider, &sites);
        assert_eq!(
            matching,
            vec!["full-match"],
            "multi-key selector requires ALL keys to match (AND semantics)"
        );
    }

    #[test]
    fn site_with_extra_labels_still_matches() {
        // Item 9 (extra labels OK): extra labels on the site don't block matching
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu")]);
        let site = test_site_with_labels("gpu-site", "net", &[("hw", "gpu"), ("zone", "us-east-1a")]);
        let matching = sites_matching_selector(&provider, &[site]);
        assert_eq!(
            matching,
            vec!["gpu-site"],
            "extra labels on site must not prevent matching"
        );
    }

    #[test]
    fn selector_wrong_value_does_not_match() {
        // Item 9 (value mismatch): key present but wrong value → no match
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu")]);
        let site = test_site_with_labels("site", "net", &[("hw", "cpu")]);
        let matching = sites_matching_selector(&provider, &[site]);
        assert!(matching.is_empty(), "wrong label value must not match the selector");
    }

    #[test]
    fn selector_missing_key_does_not_match() {
        // Item 9 (missing key): site has no matching key → no match
        let provider = test_provider_with_selector("prov", "net", &[("hw", "gpu")]);
        let site = test_site_with_labels("site", "net", &[("zone", "us-east")]);
        let matching = sites_matching_selector(&provider, &[site]);
        assert!(matching.is_empty(), "missing selector key on site must not match");
    }

    #[test]
    fn empty_selector_with_no_sites_returns_empty() {
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": {"name": "p"},
            "spec": {
                "gridNetworkRef": "net",
                "backendKind": "local",
                "endpoint": "http://vllm:8000",
                "providerKind": "self_hosted",
                "models": []
            }
        }))
        .unwrap_or_else(|_| std::process::abort());

        let matching = sites_matching_selector(&provider, &[]);
        assert!(
            matching.is_empty(),
            "passing an empty sites slice must return an empty result"
        );
    }

    // Item 13: update_status and reconcile require a live Kubernetes client.
    // They are covered at the integration level.  The pure decision logic
    // (validate_provider_config, phase_from_matching, sites_matching_selector)
    // is fully unit-tested above.

    // -----------------------------------------------------------------------
    // parse_duration_str — pure duration parsing
    // -----------------------------------------------------------------------

    #[test]
    fn duration_seconds_parses() {
        assert_eq!(parse_duration_str("5s"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration_str("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration_str("1s"), Some(Duration::from_secs(1)));
    }

    #[test]
    fn duration_milliseconds_parses() {
        assert_eq!(parse_duration_str("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration_str("100ms"), Some(Duration::from_millis(100)));
    }

    #[test]
    fn duration_unrecognised_suffix_returns_none() {
        assert_eq!(parse_duration_str("5m"), None, "minutes not supported");
        assert_eq!(parse_duration_str("5"), None, "bare number not supported");
        assert_eq!(parse_duration_str(""), None, "empty string not supported");
    }

    #[test]
    fn duration_non_numeric_returns_none() {
        assert_eq!(parse_duration_str("fives"), None, "non-numeric seconds");
        assert_eq!(parse_duration_str("abcms"), None, "non-numeric milliseconds");
    }

    // -----------------------------------------------------------------------
    // parse_probe_timeout — pure timeout derivation
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_from_health_check_config() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: None,
            path: None,
            timeout: Some("10s".to_owned()),
            tls: None,
        };
        assert_eq!(
            parse_probe_timeout(Some(&hc)),
            Duration::from_secs(10),
            "must respect configured timeout"
        );
    }

    #[test]
    fn timeout_defaults_when_absent() {
        assert_eq!(
            parse_probe_timeout(None),
            DEFAULT_PROBE_TIMEOUT,
            "absent health_check must use default timeout"
        );
    }

    #[test]
    fn timeout_defaults_when_field_absent() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: None,
            path: None,
            timeout: None,
            tls: None,
        };
        assert_eq!(
            parse_probe_timeout(Some(&hc)),
            DEFAULT_PROBE_TIMEOUT,
            "absent timeout field must use default"
        );
    }

    #[test]
    fn timeout_defaults_on_unparseable_value() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: None,
            path: None,
            timeout: Some("invalid".to_owned()),
            tls: None,
        };
        assert_eq!(
            parse_probe_timeout(Some(&hc)),
            DEFAULT_PROBE_TIMEOUT,
            "unparseable timeout must fall back to default"
        );
    }

    // -----------------------------------------------------------------------
    // requeue_interval_for_provider — pure interval derivation
    // -----------------------------------------------------------------------

    #[test]
    fn requeue_uses_default_when_no_health_check() {
        let spec = make_spec("http://vllm:8000", None, None);
        assert_eq!(
            requeue_interval_for_provider(&spec),
            REQUEUE_INTERVAL,
            "absent health_check must yield the default requeue interval (300s)"
        );
    }

    #[test]
    fn requeue_uses_default_when_interval_field_absent() {
        let spec = make_spec_with_health_check("http://vllm:8000", None, None);
        assert_eq!(
            requeue_interval_for_provider(&spec),
            REQUEUE_INTERVAL,
            "health_check without interval must yield default requeue interval"
        );
    }

    #[test]
    fn requeue_uses_configured_seconds_interval() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: Some("30s".to_owned()),
            path: None,
            timeout: None,
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            Duration::from_secs(30),
            "healthCheck.interval \"30s\" must requeue after 30 seconds"
        );
    }

    #[test]
    fn requeue_uses_configured_milliseconds_interval() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: Some("500ms".to_owned()),
            path: None,
            timeout: None,
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            Duration::from_millis(500),
            "healthCheck.interval \"500ms\" must requeue after 500ms"
        );
    }

    #[test]
    fn requeue_uses_default_for_invalid_interval_format() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: Some("5m".to_owned()),
            path: None,
            timeout: None,
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            REQUEUE_INTERVAL,
            "unparseable interval (\"5m\") must fall back to default 300s"
        );
    }

    #[test]
    fn requeue_uses_default_for_bare_number_interval() {
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: Some("30".to_owned()),
            path: None,
            timeout: None,
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            REQUEUE_INTERVAL,
            "bare number without suffix (\"30\") must fall back to default"
        );
    }

    #[test]
    fn requeue_interval_and_probe_timeout_are_independent() {
        // interval controls reconcile cadence; timeout controls HTTP probe wait.
        // Changing one must not affect the other.
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: Some("60s".to_owned()),
            path: Some("/health".to_owned()),
            timeout: Some("3s".to_owned()),
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            Duration::from_secs(60),
            "requeue interval must use the interval field"
        );
        assert_eq!(
            parse_probe_timeout(spec.health_check.as_ref()),
            Duration::from_secs(3),
            "probe timeout must use the timeout field"
        );
    }

    #[test]
    fn requeue_interval_does_not_use_timeout_field() {
        // A spec with timeout but no interval must use the default requeue.
        let hc = HealthCheckConfig {
            endpoint: None,
            interval: None,
            path: None,
            timeout: Some("10s".to_owned()),
            tls: None,
        };
        let spec = make_spec_with_health_check_config("http://vllm:8000", Some(hc));
        assert_eq!(
            requeue_interval_for_provider(&spec),
            REQUEUE_INTERVAL,
            "timeout field must not affect the requeue interval"
        );
    }

    #[test]
    fn requeue_uses_tls_interval_when_metrics_tls_configured() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://vllm:8443",
            "models": [{"name": "model"}],
            "metricsConfig": {
                "tls": {
                    "caSecretRef": { "name": "ca", "namespace": "ns" }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            requeue_interval_for_provider(&spec),
            TLS_REQUEUE_INTERVAL,
            "provider with metricsConfig.tls must use shorter TLS requeue interval"
        );
    }

    #[test]
    fn requeue_interval_below_tls_bound_passes_through() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://vllm:8443",
            "models": [{"name": "model"}],
            "healthCheck": { "interval": "30s" },
            "metricsConfig": {
                "tls": {
                    "caSecretRef": { "name": "ca", "namespace": "ns" }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            requeue_interval_for_provider(&spec),
            Duration::from_secs(30),
            "healthCheck.interval below TLS bound must pass through unchanged"
        );
    }

    #[test]
    fn requeue_interval_above_tls_bound_is_capped() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://vllm:8443",
            "models": [{"name": "model"}],
            "healthCheck": { "interval": "120s" },
            "metricsConfig": {
                "tls": {
                    "caSecretRef": { "name": "ca", "namespace": "ns" }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            requeue_interval_for_provider(&spec),
            TLS_REQUEUE_INTERVAL,
            "healthCheck.interval exceeding TLS bound must be capped to 60s"
        );
    }

    // -----------------------------------------------------------------------
    // probe_url_for_provider — pure URL construction
    // -----------------------------------------------------------------------

    #[test]
    fn probe_url_absent_health_check_returns_none() {
        let spec = make_spec("http://vllm:8000", None, None);
        assert!(
            probe_url_for_provider(&spec).is_none(),
            "no health_check config must yield None (NotProbed)"
        );
    }

    #[test]
    fn probe_url_uses_default_path() {
        let spec = make_spec_with_health_check("http://vllm:8000", None, None);
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("http://vllm:8000/health"),
            "must append default /health when path is absent"
        );
    }

    #[test]
    fn probe_url_uses_custom_path() {
        let spec = make_spec("http://vllm:8000", Some("/v1/models"), None);
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("http://vllm:8000/v1/models"),
            "custom path must be used verbatim"
        );
    }

    #[test]
    fn probe_url_adds_leading_slash_to_custom_path() {
        let spec = make_spec("http://vllm:8000", Some("ready"), None);
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("http://vllm:8000/ready"),
            "custom path without leading slash must be normalized"
        );
    }

    #[test]
    fn probe_url_strips_trailing_slash_from_endpoint() {
        let spec = make_spec("http://vllm:8000/", Some("/health"), None);
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("http://vllm:8000/health"),
            "trailing slash on endpoint must be stripped before appending path"
        );
    }

    #[test]
    fn probe_url_passes_https_through() {
        // HTTPS URLs are returned as-is; probe_endpoint rejects them.
        let spec = make_spec("https://api.example.com", Some("/health"), None);
        assert!(
            probe_url_for_provider(&spec).is_some(),
            "https URL is returned; probe_endpoint will reject it"
        );
    }

    // -----------------------------------------------------------------------
    // probe_url_for_provider — endpoint override
    // -----------------------------------------------------------------------

    #[test]
    fn probe_url_uses_health_check_endpoint_override() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://backend:8080",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "endpoint": "https://epp-service:9090",
                "path": "/healthz"
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("https://epp-service:9090/healthz"),
            "healthCheck.endpoint must override spec.endpoint"
        );
    }

    #[test]
    fn probe_url_falls_back_to_spec_endpoint_when_override_absent() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://backend:8080",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "path": "/healthz"
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("http://backend:8080/healthz"),
            "absent healthCheck.endpoint must fall back to spec.endpoint"
        );
    }

    #[test]
    fn probe_url_blank_health_check_endpoint_passes_through() {
        // A blank endpoint is a misconfiguration.  probe_url_for_provider
        // passes it through so probe_endpoint will fail with Unavailable,
        // surfacing the error instead of silently skipping the probe.
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://backend:8080",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "endpoint": "   ",
                "path": "/health"
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert!(
            probe_url_for_provider(&spec).is_some(),
            "blank healthCheck.endpoint must pass through (probe_endpoint will reject it)"
        );
    }

    #[test]
    fn probe_url_endpoint_override_strips_trailing_slash() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://backend:8080",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "endpoint": "https://epp:9090/",
                "path": "/healthz"
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            probe_url_for_provider(&spec).as_deref(),
            Some("https://epp:9090/healthz"),
            "trailing slash on healthCheck.endpoint must be stripped"
        );
    }

    // -----------------------------------------------------------------------
    // requeue_interval_for_provider — healthCheck.tls triggers TLS interval
    // -----------------------------------------------------------------------

    #[test]
    fn requeue_uses_tls_interval_for_health_check_tls() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://vllm:8443",
            "models": [{"name": "model"}],
            "healthCheck": {
                "path": "/health",
                "tls": {
                    "caSecretRef": { "name": "ca", "namespace": "ns" }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            requeue_interval_for_provider(&spec),
            TLS_REQUEUE_INTERVAL,
            "provider with healthCheck.tls must use shorter TLS requeue interval"
        );
    }

    #[test]
    fn requeue_interval_below_hc_tls_bound_passes_through() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://vllm:8443",
            "models": [{"name": "model"}],
            "healthCheck": {
                "interval": "30s",
                "path": "/health",
                "tls": {
                    "caSecretRef": { "name": "ca", "namespace": "ns" }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            requeue_interval_for_provider(&spec),
            Duration::from_secs(30),
            "healthCheck.interval below TLS bound must pass through unchanged (healthCheck.tls)"
        );
    }

    // -----------------------------------------------------------------------
    // HealthCheckConfig serde — endpoint + tls fields round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn health_check_config_with_endpoint_deserializes() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "http://backend:8080",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "endpoint": "https://epp:9090",
                "path": "/healthz",
                "interval": "30s",
                "timeout": "5s"
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let hc = spec.health_check.unwrap_or_else(|| std::process::abort());
        assert_eq!(
            hc.endpoint.as_deref(),
            Some("https://epp:9090"),
            "endpoint must round-trip"
        );
        assert_eq!(hc.path.as_deref(), Some("/healthz"), "path must round-trip");
        assert_eq!(hc.interval.as_deref(), Some("30s"), "interval must round-trip");
        assert_eq!(hc.timeout.as_deref(), Some("5s"), "timeout must round-trip");
        assert!(hc.tls.is_none(), "absent tls must be None");
    }

    #[test]
    fn health_check_config_with_tls_deserializes() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://backend:8443",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "path": "/health",
                "tls": {
                    "caSecretRef": {
                        "name": "backend-ca",
                        "namespace": "grid-system"
                    }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let hc = spec.health_check.unwrap_or_else(|| std::process::abort());
        let tls = hc.tls.unwrap_or_else(|| std::process::abort());
        assert_eq!(tls.ca_secret_ref.name, "backend-ca", "caSecretRef.name must round-trip");
        assert_eq!(
            tls.ca_secret_ref.namespace, "grid-system",
            "caSecretRef.namespace must round-trip"
        );
        assert!(
            tls.client_certificate_secret_ref.is_none(),
            "absent clientCertificateSecretRef must be None"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "tests multiple TLS fields in one assertion block")]
    fn health_check_config_with_tls_and_client_cert_deserializes() {
        let spec: InferenceProviderSpec = serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": "https://backend:8443",
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "path": "/health",
                "tls": {
                    "caSecretRef": {
                        "name": "backend-ca",
                        "namespace": "grid-system"
                    },
                    "clientCertificateSecretRef": {
                        "name": "client-cert",
                        "namespace": "grid-system"
                    }
                }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let hc = spec.health_check.unwrap_or_else(|| std::process::abort());
        let tls = hc.tls.unwrap_or_else(|| std::process::abort());
        let client_ref = tls
            .client_certificate_secret_ref
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(client_ref.name, "client-cert", "client cert name must round-trip");
        assert_eq!(
            client_ref.namespace, "grid-system",
            "client cert namespace must round-trip"
        );
        assert_eq!(
            client_ref.certificate_key, "tls.crt",
            "certificateKey must default to tls.crt"
        );
        assert_eq!(
            client_ref.private_key_key, "tls.key",
            "privateKeyKey must default to tls.key"
        );
    }

    // -----------------------------------------------------------------------
    // TlsFailureReason — healthCheck prefix
    // -----------------------------------------------------------------------

    #[test]
    fn tls_failure_reason_health_check_prefix_stable_values() {
        use crate::resources::endpoint_tls::TlsFailureReason;

        assert_eq!(
            TlsFailureReason::SecretMissing.as_status_reason("HealthCheck"),
            "HealthCheckTlsSecretMissing",
            "stable status reason code"
        );
        assert_eq!(
            TlsFailureReason::KeyMissing.as_status_reason("HealthCheck"),
            "HealthCheckTlsKeyMissing",
            "stable status reason code"
        );
        assert_eq!(
            TlsFailureReason::MaterialInvalid.as_status_reason("HealthCheck"),
            "HealthCheckTlsMaterialInvalid",
            "stable status reason code"
        );
        assert_eq!(
            TlsFailureReason::IdentityMismatch.as_status_reason("HealthCheck"),
            "HealthCheckTlsIdentityMismatch",
            "stable status reason code"
        );
    }

    // -----------------------------------------------------------------------
    // probe_endpoint — async, local TcpListener (no external network)
    // -----------------------------------------------------------------------

    /// Start a local HTTP server on a random port that returns one canned response.
    ///
    /// The server accepts one connection, reads the request, writes `response`,
    /// then closes.  Works for both the old raw-TCP path and the new hyper path
    /// because hyper parses the HTTP/1.0 status line correctly.
    async fn start_test_server(response: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|_| std::process::abort());
        let port = listener.local_addr().unwrap_or_else(|_| std::process::abort()).port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Read and discard the request.
                let mut buf = [0_u8; 4096];
                drop(stream.read(&mut buf).await);
                // Write the canned response.
                drop(stream.write_all(response).await);
                // stream drops here, closing the connection.
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn probe_http_200_yields_healthy() {
        let url = start_test_server(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(result, ProbeOutcome::Healthy, "HTTP 200 response must yield Healthy");
    }

    #[tokio::test]
    async fn probe_http_204_yields_healthy() {
        let url = start_test_server(b"HTTP/1.0 204 No Content\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(result, ProbeOutcome::Healthy, "HTTP 204 response must yield Healthy");
    }

    #[tokio::test]
    async fn probe_http_500_yields_degraded() {
        let url = start_test_server(b"HTTP/1.0 500 Internal Server Error\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(result, ProbeOutcome::Degraded, "HTTP 500 response must yield Degraded");
    }

    #[tokio::test]
    async fn probe_http_503_yields_degraded() {
        let url = start_test_server(b"HTTP/1.0 503 Service Unavailable\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(result, ProbeOutcome::Degraded, "HTTP 503 must yield Degraded");
    }

    #[tokio::test]
    async fn probe_http_404_yields_degraded() {
        let url = start_test_server(b"HTTP/1.0 404 Not Found\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(result, ProbeOutcome::Degraded, "HTTP 404 must yield Degraded");
    }

    #[tokio::test]
    async fn probe_http_301_yields_degraded() {
        let url = start_test_server(b"HTTP/1.0 301 Moved Permanently\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(
            result,
            ProbeOutcome::Degraded,
            "HTTP 301 (redirect) must yield Degraded"
        );
    }

    #[tokio::test]
    async fn probe_unreachable_endpoint_yields_unavailable() {
        // Nothing is listening on this port; connection must fail.
        let result = probe_endpoint("http://127.0.0.1:1", Duration::from_secs(5), None).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "connection refused must yield Unavailable"
        );
    }

    #[tokio::test]
    async fn probe_https_tls_handshake_failure_yields_unavailable() {
        // A plain (non-TLS) TCP server immediately closes each accepted
        // connection.  hyper-rustls will attempt a TLS handshake, receive
        // EOF, and return a transport error → Unavailable.
        // This proves HTTPS is now *attempted* (not short-circuited) and
        // that TLS errors map correctly to Unavailable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|_| std::process::abort());
        let port = listener.local_addr().unwrap_or_else(|_| std::process::abort()).port();
        tokio::spawn(async move {
            // Accept the connection then drop the stream immediately.
            // The client receives EOF during the TLS handshake.
            if let Ok((_stream, _)) = listener.accept().await {}
        });
        let url = format!("https://127.0.0.1:{port}");
        let result = probe_endpoint(&url, Duration::from_secs(5), None).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "TLS handshake failure against a plain-TCP server must yield Unavailable"
        );
    }

    #[tokio::test]
    async fn probe_unsupported_scheme_ftp_yields_unavailable() {
        // ftp:// is not http or https — must be rejected immediately without
        // attempting a connection.
        let result = probe_endpoint("ftp://example.com/file", Duration::from_secs(1), None).await;
        assert_eq!(result, ProbeOutcome::Unavailable, "ftp:// must yield Unavailable");
    }

    #[tokio::test]
    async fn probe_unsupported_scheme_file_yields_unavailable() {
        let result = probe_endpoint("file:///etc/passwd", Duration::from_secs(1), None).await;
        assert_eq!(result, ProbeOutcome::Unavailable, "file:// must yield Unavailable");
    }

    #[tokio::test]
    async fn probe_no_scheme_yields_unavailable() {
        // A path-only URL has no scheme — URL parse may succeed but scheme is None.
        let result = probe_endpoint("/just/a/path", Duration::from_secs(1), None).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "no-scheme URL must yield Unavailable"
        );
    }

    #[tokio::test]
    async fn probe_unparseable_url_yields_unavailable() {
        let result = probe_endpoint("not-a-url", Duration::from_secs(1), None).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "unparseable URL must yield Unavailable"
        );
    }

    #[tokio::test]
    async fn probe_timeout_yields_unavailable() {
        use tokio::io::AsyncReadExt as _;
        // Server accepts connection and reads the request but never responds.
        // The probe must time out and return Unavailable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|_| std::process::abort());
        let port = listener.local_addr().unwrap_or_else(|_| std::process::abort()).port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0_u8; 4096];
                drop(stream.read(&mut buf).await);
                // Intentionally never write a response.
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(stream);
            }
        });
        let url = format!("http://127.0.0.1:{port}");
        let result = probe_endpoint(&url, Duration::from_millis(100), None).await;
        assert_eq!(result, ProbeOutcome::Unavailable, "timeout must yield Unavailable");
    }

    // -----------------------------------------------------------------------
    // probe_endpoint — TLS tests (real certificates, real handshakes)
    // -----------------------------------------------------------------------

    /// Start a one-shot TLS server on localhost and return the URL.
    ///
    /// Mirrors `metrics_scraper::tests::start_tls_test_server` but lives
    /// in this module so it can be used by `probe_endpoint` TLS tests.
    #[cfg(not(feature = "fips"))]
    async fn start_tls_test_server(server_cert_pem: &str, server_key_pem: &str, response: Vec<u8>) -> String {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let server_certs = CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let server_key = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
            .unwrap();

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(tls_stream) = acceptor.accept(stream).await
            {
                let (mut reader, mut writer) = tokio::io::split(tls_stream);
                let mut buf = [0_u8; 4096];
                drop(reader.read(&mut buf).await);
                drop(writer.write_all(&response).await);
            }
        });

        format!("https://localhost:{port}")
    }

    /// OpenSSL twin of the one-shot TLS server for `fips` probe tests.
    #[cfg(feature = "fips")]
    #[expect(clippy::too_many_lines, reason = "OpenSSL test server setup")]
    async fn start_tls_test_server(server_cert_pem: &str, server_key_pem: &str, response: Vec<u8>) -> String {
        use openssl::{
            pkey::PKey,
            ssl::{Ssl, SslAcceptor, SslMethod},
            x509::X509,
        };
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let cert = X509::from_pem(server_cert_pem.as_bytes()).unwrap();
        let key = PKey::private_key_from_pem(server_key_pem.as_bytes()).unwrap();
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_certificate(&cert).unwrap();
        builder.set_private_key(&key).unwrap();
        builder.check_private_key().unwrap();
        let acceptor = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(ssl) = Ssl::new(acceptor.context()) else {
                return;
            };
            let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
                return;
            };
            if std::pin::Pin::new(&mut tls).accept().await.is_ok() {
                let (mut reader, mut writer) = tokio::io::split(tls);
                let mut buf = [0_u8; 4096];
                drop(reader.read(&mut buf).await);
                drop(writer.write_all(&response).await);
            }
        });

        format!("https://localhost:{port}")
    }

    #[tokio::test]
    async fn probe_tls_with_matching_ca_yields_healthy() {
        let ca = certs::generate_ca("test-ca").unwrap();
        let server_cert = certs::generate_dns_cert(&ca, "test-server", "localhost").unwrap();
        let url = start_tls_test_server(
            &server_cert.cert_pem,
            &server_cert.key_pem,
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        )
        .await;
        let tls_config = crate::metrics_scraper::build_tls_client_config(ca.cert_pem.as_bytes(), None, None).unwrap();
        let result = probe_endpoint(&url, Duration::from_secs(5), Some(Arc::new(tls_config))).await;
        assert_eq!(
            result,
            ProbeOutcome::Healthy,
            "TLS probe with matching CA must yield Healthy"
        );
    }

    #[tokio::test]
    async fn probe_tls_with_wrong_ca_yields_unavailable() {
        let ca_server = certs::generate_ca("server-ca").unwrap();
        let ca_wrong = certs::generate_ca("wrong-ca").unwrap();
        let server_cert = certs::generate_dns_cert(&ca_server, "test-server", "localhost").unwrap();
        let url = start_tls_test_server(
            &server_cert.cert_pem,
            &server_cert.key_pem,
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        )
        .await;
        // Client trusts wrong CA — handshake must fail.
        let tls_config =
            crate::metrics_scraper::build_tls_client_config(ca_wrong.cert_pem.as_bytes(), None, None).unwrap();
        let result = probe_endpoint(&url, Duration::from_secs(5), Some(Arc::new(tls_config))).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "TLS probe with wrong CA must yield Unavailable"
        );
    }

    #[tokio::test]
    async fn probe_http_url_with_tls_config_yields_unavailable() {
        // http:// URL with a TLS config is a misconfiguration — fail-closed.
        let ca = certs::generate_ca("test-ca").unwrap();
        let tls_config = crate::metrics_scraper::build_tls_client_config(ca.cert_pem.as_bytes(), None, None).unwrap();
        let url = start_test_server(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let result = probe_endpoint(&url, Duration::from_secs(5), Some(Arc::new(tls_config))).await;
        assert_eq!(
            result,
            ProbeOutcome::Unavailable,
            "http:// URL with TLS config must yield Unavailable (fail-closed)"
        );
    }

    // -----------------------------------------------------------------------
    // parse_duration_str — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_duration_str_whitespace_in_numeric_part_is_trimmed() {
        // The numeric part is trimmed via `.trim()` before parsing,
        // so surrounding whitespace on the number is accepted.
        assert_eq!(
            parse_duration_str("  5s"),
            Some(Duration::from_secs(5)),
            "leading whitespace before number must be trimmed"
        );
        assert_eq!(
            parse_duration_str("100  ms"),
            Some(Duration::from_millis(100)),
            "whitespace between number and suffix is trimmed from the numeric part"
        );
        assert_eq!(
            parse_duration_str("  500  ms"),
            Some(Duration::from_millis(500)),
            "whitespace on both sides of number must be trimmed"
        );
    }

    // -----------------------------------------------------------------------
    // probe_endpoint — sequential / state isolation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn probe_http_two_sequential_probes_use_independent_state() {
        // Each probe_endpoint call creates a fresh hyper Client (no shared
        // connection pool).  Calling it twice must not corrupt state or leave
        // dangling connections.
        let url1 = start_test_server(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let url2 = start_test_server(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let r1 = probe_endpoint(&url1, Duration::from_secs(5), None).await;
        let r2 = probe_endpoint(&url2, Duration::from_secs(5), None).await;
        assert_eq!(r1, ProbeOutcome::Healthy, "first sequential probe must yield Healthy");
        assert_eq!(r2, ProbeOutcome::Healthy, "second sequential probe must yield Healthy");
    }

    #[tokio::test]
    async fn probe_http_then_https_failure_are_independent() {
        // A successful HTTP probe followed by an HTTPS failure must not
        // interfere with each other.
        let http_url = start_test_server(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let plain_outcome = probe_endpoint(&http_url, Duration::from_secs(5), None).await;

        // HTTPS probe against a non-TLS server → Unavailable (TLS error).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|_| std::process::abort());
        let port = listener.local_addr().unwrap_or_else(|_| std::process::abort()).port();
        tokio::spawn(async move { if let Ok((_stream, _)) = listener.accept().await {} });
        let tls_outcome = probe_endpoint(&format!("https://127.0.0.1:{port}"), Duration::from_secs(5), None).await;

        assert_eq!(
            plain_outcome,
            ProbeOutcome::Healthy,
            "HTTP probe must succeed independently"
        );
        assert_eq!(
            tls_outcome,
            ProbeOutcome::Unavailable,
            "HTTPS TLS error must yield Unavailable independently"
        );
    }

    // -----------------------------------------------------------------------
    // Integration: static config still short-circuits before probe
    // -----------------------------------------------------------------------

    #[test]
    fn blank_endpoint_short_circuits_before_probe() {
        // validate_provider_config catches blank endpoint immediately;
        // probe_url_for_provider would also return None for a blank endpoint,
        // but the static validation check runs first in resolve_phase_and_sites.
        let provider: InferenceProvider = serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis-proxy.io/v1alpha1",
            "kind": "InferenceProvider",
            "metadata": { "name": "bad" },
            "spec": {
                "gridNetworkRef": "net",
                "providerKind": "self_hosted",
                "backendKind": "local",
                "endpoint": "",
                "models": [{"name": "model"}],
                "healthCheck": { "path": "/health" }
            }
        }))
        .unwrap_or_else(|_| std::process::abort());
        let err = validate_provider_config(&provider);
        assert!(
            err.is_some(),
            "blank endpoint must fail static validation before probe runs"
        );
    }

    #[test]
    fn no_health_check_config_means_not_probed() {
        // probe_url_for_provider returns None → ProbeOutcome::NotProbed
        // → phase_from_probe preserves site_phase unchanged.
        let spec = make_spec("http://vllm:8000", None, None);
        assert!(
            probe_url_for_provider(&spec).is_none(),
            "absent health_check must yield NotProbed path"
        );
        let phase = phase_from_probe(ProbeOutcome::NotProbed, ProviderPhase::Available);
        assert_eq!(phase, ProviderPhase::Available, "NotProbed must preserve Available");
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn make_spec(endpoint: &str, health_path: Option<&str>, timeout: Option<&str>) -> InferenceProviderSpec {
        serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": endpoint,
            "models": [{"name": "model-a"}],
            "healthCheck": if health_path.is_some() || timeout.is_some() {
                serde_json::json!({
                    "path": health_path,
                    "timeout": timeout
                })
            } else {
                serde_json::Value::Null
            }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    fn make_spec_with_health_check(
        endpoint: &str,
        health_path: Option<&str>,
        timeout: Option<&str>,
    ) -> InferenceProviderSpec {
        serde_json::from_value(serde_json::json!({
            "gridNetworkRef": "net",
            "providerKind": "self_hosted",
            "backendKind": "local",
            "endpoint": endpoint,
            "models": [{"name": "model-a"}],
            "healthCheck": {
                "path": health_path,
                "timeout": timeout
            }
        }))
        .unwrap_or_else(|_| std::process::abort())
    }

    /// Build a spec with a fully specified [`HealthCheckConfig`].
    ///
    /// Used by interval tests that need to control all three `HealthCheckConfig`
    /// fields independently without going through the JSON shorthand helpers.
    fn make_spec_with_health_check_config(
        endpoint: &str,
        health_check: Option<HealthCheckConfig>,
    ) -> InferenceProviderSpec {
        InferenceProviderSpec {
            capacity_weight: None,
            grid_network_ref: "net".to_owned(),
            access_policy: crate::crd::auth::AccessPolicy::default(),
            auth: None,
            backend_kind: "local".to_owned(),
            gateway_ref: None,
            cost: None,
            endpoint: endpoint.to_owned(),
            health_check,
            models: vec![crate::crd::inference_provider::ModelInfo {
                name: "model-a".to_owned(),
                capabilities: Vec::new(),
                context_window: None,
            }],
            model_discovery: None,
            provider_kind: "self_hosted".to_owned(),
            routing_cluster_ref: None,
            metrics_config: None,
            traffic_policy: None,
            site_selector: crate::crd::auth::SelectorConfig::default(),
        }
    }
}
