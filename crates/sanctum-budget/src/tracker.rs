//! Budget tracker for monitoring LLM spend across sessions and days.
//!
//! Tracks per-provider spending with session and daily limits,
//! supports persistence to disk, and handles day-boundary resets.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};

use crate::error::BudgetError;
use crate::parser::UsageData;
use crate::pricing;
use crate::provider::Provider;
use sanctum_types::config::BudgetConfig;

/// Tracks LLM API spending against configured budgets.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    /// When the current session started.
    session_start: DateTime<Utc>,
    /// When the current daily period started.
    daily_start: DateTime<Utc>,
    /// Accumulated session spend per provider (in cents).
    session_spend: HashMap<Provider, u64>,
    /// Accumulated daily spend per provider (in cents).
    daily_spend: HashMap<Provider, u64>,
    /// Per-provider session limits (in cents). `None` means no limit.
    session_limits: HashMap<Provider, Option<u64>>,
    /// Per-provider daily limits (in cents). `None` means no limit.
    daily_limits: HashMap<Provider, Option<u64>>,
    /// Default session limit when no per-provider override exists.
    default_session_limit: Option<u64>,
    /// Default daily limit when no per-provider override exists.
    default_daily_limit: Option<u64>,
    /// Alert notification threshold as a percentage (0-100).
    alert_at_percent: u8,
}

/// Snapshot of budget status for a single provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetStatus {
    /// The provider this status is for.
    pub provider: Provider,
    /// Cents spent in the current session.
    pub session_spent_cents: u64,
    /// Session limit in cents, if configured.
    pub session_limit_cents: Option<u64>,
    /// Cents spent today.
    pub daily_spent_cents: u64,
    /// Daily limit in cents, if configured.
    pub daily_limit_cents: Option<u64>,
    /// Whether the alert threshold has been crossed.
    pub alert_triggered: bool,
    /// Whether the session limit has been exceeded.
    pub session_exceeded: bool,
    /// Whether the daily limit has been exceeded.
    pub daily_exceeded: bool,
}

/// Serializable state for persistence.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    session_start: DateTime<Utc>,
    daily_start: DateTime<Utc>,
    session_spend: HashMap<Provider, u64>,
    daily_spend: HashMap<Provider, u64>,
}

impl BudgetTracker {
    /// Create a new budget tracker from configuration.
    ///
    /// Loads the default session/daily limits and then applies any
    /// per-provider overrides from `config.providers`.
    #[must_use]
    pub fn new(config: &BudgetConfig) -> Self {
        let now = Utc::now();
        let mut session_limits = HashMap::new();
        let mut daily_limits = HashMap::new();

        // Apply per-provider overrides from config
        for (key, prov_cfg) in &config.providers {
            if let Some(provider) = parse_provider(key) {
                if let Some(ref amount) = prov_cfg.session {
                    session_limits.insert(provider, Some(amount.cents));
                }
                if let Some(ref amount) = prov_cfg.daily {
                    daily_limits.insert(provider, Some(amount.cents));
                }
            }
        }

        Self {
            session_start: now,
            daily_start: now,
            session_spend: HashMap::new(),
            daily_spend: HashMap::new(),
            session_limits,
            daily_limits,
            default_session_limit: config.default_session.as_ref().map(|b| b.cents),
            default_daily_limit: config.default_daily.as_ref().map(|b| b.cents),
            alert_at_percent: config.alert_at_percent,
        }
    }

    /// Record a usage event and return the updated budget status.
    pub fn record_usage(&mut self, usage: &UsageData) -> BudgetStatus {
        let cost = pricing::calculate_cost(
            usage.provider,
            &usage.model,
            usage.input_tokens,
            usage.output_tokens,
        );

        let session_entry = self.session_spend.entry(usage.provider).or_insert(0);
        *session_entry = session_entry.saturating_add(cost);

        let daily_entry = self.daily_spend.entry(usage.provider).or_insert(0);
        *daily_entry = daily_entry.saturating_add(cost);

        self.status(usage.provider)
    }

    /// Get the current budget status for a provider.
    #[must_use]
    pub fn status(&self, provider: Provider) -> BudgetStatus {
        let session_spent = self.session_spend.get(&provider).copied().unwrap_or(0);
        let daily_spent = self.daily_spend.get(&provider).copied().unwrap_or(0);

        let session_limit = self
            .session_limits
            .get(&provider)
            .copied()
            .flatten()
            .or(self.default_session_limit);

        let daily_limit = self
            .daily_limits
            .get(&provider)
            .copied()
            .flatten()
            .or(self.default_daily_limit);

        let session_exceeded = session_limit.is_some_and(|limit| session_spent >= limit);
        let daily_exceeded = daily_limit.is_some_and(|limit| daily_spent >= limit);

        let alert_triggered = self.is_alert_triggered(session_spent, session_limit)
            || self.is_alert_triggered(daily_spent, daily_limit);

        BudgetStatus {
            provider,
            session_spent_cents: session_spent,
            session_limit_cents: session_limit,
            daily_spent_cents: daily_spent,
            daily_limit_cents: daily_limit,
            alert_triggered,
            session_exceeded,
            daily_exceeded,
        }
    }

    /// Get budget status for all known providers.
    #[must_use]
    pub fn all_statuses(&self) -> Vec<BudgetStatus> {
        let providers = [Provider::OpenAI, Provider::Anthropic, Provider::Google];
        providers.iter().map(|p| self.status(*p)).collect()
    }

    /// Set the default session limit in cents.
    pub const fn set_default_session_limit(&mut self, limit: Option<u64>) {
        self.default_session_limit = limit;
    }

    /// Set the default daily limit in cents.
    pub const fn set_default_daily_limit(&mut self, limit: Option<u64>) {
        self.default_daily_limit = limit;
    }

    /// Extend the session limit for a provider by the given amount in cents.
    pub fn extend_session(&mut self, provider: Provider, additional_cents: u64) {
        let current = self
            .session_limits
            .get(&provider)
            .copied()
            .flatten()
            .or(self.default_session_limit)
            .unwrap_or(0);

        self.session_limits
            .insert(provider, Some(current.saturating_add(additional_cents)));
    }

    /// Reset all session spending and start a new session.
    pub fn reset_session(&mut self) {
        self.session_spend.clear();
        self.session_start = Utc::now();
    }

    /// Reset all daily spending and start a new daily period.
    pub fn reset_daily(&mut self) {
        self.daily_spend.clear();
        self.daily_start = Utc::now();
    }

    /// Reset daily spending if we've crossed into a new calendar day (UTC).
    pub fn maybe_reset_daily(&mut self) {
        let now = Utc::now();
        if now.ordinal() != self.daily_start.ordinal() || now.year() != self.daily_start.year() {
            self.reset_daily();
        }
    }

    /// Save the current tracker state to a file.
    ///
    /// # Errors
    ///
    /// Returns `BudgetError::Io` or `BudgetError::Serde` on failure.
    pub fn save_to_file(&self, path: &Path) -> Result<(), BudgetError> {
        use std::io::Write;

        let state = PersistedState {
            session_start: self.session_start,
            daily_start: self.daily_start,
            session_spend: self.session_spend.clone(),
            daily_spend: self.daily_spend.clone(),
        };
        let json = serde_json::to_string_pretty(&state)?;

        let tmp_path = path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        Ok(())
    }

    /// Load tracker state from a file, merging with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `BudgetError::Io` or `BudgetError::Serde` on failure.
    pub fn load_from_file(path: &Path, config: &BudgetConfig) -> Result<Self, BudgetError> {
        let data = std::fs::read_to_string(path)?;
        let state: PersistedState = serde_json::from_str(&data)?;

        let mut session_limits = HashMap::new();
        let mut daily_limits = HashMap::new();

        for (key, prov_cfg) in &config.providers {
            if let Some(provider) = parse_provider(key) {
                if let Some(ref amount) = prov_cfg.session {
                    session_limits.insert(provider, Some(amount.cents));
                }
                if let Some(ref amount) = prov_cfg.daily {
                    daily_limits.insert(provider, Some(amount.cents));
                }
            }
        }

        Ok(Self {
            session_start: state.session_start,
            daily_start: state.daily_start,
            session_spend: state.session_spend,
            daily_spend: state.daily_spend,
            session_limits,
            daily_limits,
            default_session_limit: config.default_session.as_ref().map(|b| b.cents),
            default_daily_limit: config.default_daily.as_ref().map(|b| b.cents),
            alert_at_percent: config.alert_at_percent,
        })
    }

    /// Check if the alert threshold has been crossed.
    fn is_alert_triggered(&self, spent: u64, limit: Option<u64>) -> bool {
        if let Some(limit) = limit {
            if limit == 0 {
                return spent > 0;
            }
            let percent = spent.saturating_mul(100) / limit;
            percent >= u64::from(self.alert_at_percent)
        } else {
            false
        }
    }
}

/// Parse a provider name string (case-insensitive) into a `Provider`.
fn parse_provider(key: &str) -> Option<Provider> {
    match key.to_lowercase().as_str() {
        "openai" => Some(Provider::OpenAI),
        "anthropic" => Some(Provider::Anthropic),
        "google" => Some(Provider::Google),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sanctum_types::config::BudgetAmount;

    fn test_config() -> BudgetConfig {
        BudgetConfig {
            default_session: Some(BudgetAmount { cents: 5000 }),
            default_daily: Some(BudgetAmount { cents: 20000 }),
            alert_at_percent: 75,
            ..BudgetConfig::default()
        }
    }

    fn make_usage(provider: Provider, model: &str, input: u64, output: u64) -> UsageData {
        UsageData {
            provider,
            model: model.to_string(),
            input_tokens: input,
            output_tokens: output,
        }
    }

    #[test]
    fn zero_initial_spend() {
        let tracker = BudgetTracker::new(&test_config());
        let status = tracker.status(Provider::OpenAI);
        assert_eq!(status.session_spent_cents, 0);
        assert_eq!(status.daily_spent_cents, 0);
        assert!(!status.session_exceeded);
        assert!(!status.daily_exceeded);
        assert!(!status.alert_triggered);
    }

    #[test]
    fn accumulation() {
        let mut tracker = BudgetTracker::new(&test_config());

        // Record usage: 1M input at 250c/M = 250c, 500K output at 1000c/M = 500c
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 500_000);
        tracker.record_usage(&usage);

        let status = tracker.status(Provider::OpenAI);
        assert_eq!(status.session_spent_cents, 750);
        assert_eq!(status.daily_spent_cents, 750);

        // Record more - should accumulate
        tracker.record_usage(&usage);
        let status = tracker.status(Provider::OpenAI);
        assert_eq!(status.session_spent_cents, 1500);
        assert_eq!(status.daily_spent_cents, 1500);
    }

    #[test]
    fn session_limit_detection() {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 100 }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        // gpt-4o: 1M input = 250 cents > 100 cent limit
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let status = tracker.record_usage(&usage);

        assert!(status.session_exceeded);
        assert_eq!(status.session_spent_cents, 250);
        assert_eq!(status.session_limit_cents, Some(100));
    }

    #[test]
    fn daily_limit_detection() {
        let config = BudgetConfig {
            default_session: None,
            default_daily: Some(BudgetAmount { cents: 100 }),
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let status = tracker.record_usage(&usage);

        assert!(status.daily_exceeded);
        assert_eq!(status.daily_spent_cents, 250);
        assert_eq!(status.daily_limit_cents, Some(100));
    }

    #[test]
    fn alert_at_threshold() {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 1000 }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        // gpt-4o: 1M input = 250c, 500K output = 500c -> total 750c = 75% of 1000
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 500_000);
        let status = tracker.record_usage(&usage);

        assert_eq!(status.session_spent_cents, 750);
        assert!(status.alert_triggered);
        assert!(!status.session_exceeded);
    }

    #[test]
    fn no_alert_below_threshold() {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 10000 }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        // 250 out of 10000 = 2.5%
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let status = tracker.record_usage(&usage);

        assert!(!status.alert_triggered);
    }

    #[test]
    fn extend_session() {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 100 }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let status = tracker.record_usage(&usage);
        assert!(status.session_exceeded);

        // Extend by 500 cents -> new limit is 600
        tracker.extend_session(Provider::OpenAI, 500);
        let status = tracker.status(Provider::OpenAI);
        assert!(!status.session_exceeded);
        assert_eq!(status.session_limit_cents, Some(600));
    }

    #[test]
    fn reset_session_clears_session_only() {
        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 1_000_000);
        tracker.record_usage(&usage);

        let before_daily = tracker.status(Provider::OpenAI).daily_spent_cents;
        assert!(tracker.status(Provider::OpenAI).session_spent_cents > 0);

        tracker.reset_session();

        assert_eq!(tracker.status(Provider::OpenAI).session_spent_cents, 0);
        // Daily spend should remain
        assert_eq!(
            tracker.status(Provider::OpenAI).daily_spent_cents,
            before_daily
        );
    }

    #[test]
    fn reset_daily() {
        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 1_000_000);
        tracker.record_usage(&usage);

        assert!(tracker.status(Provider::OpenAI).daily_spent_cents > 0);

        tracker.reset_daily();

        assert_eq!(tracker.status(Provider::OpenAI).daily_spent_cents, 0);
    }

    #[test]
    fn day_boundary_reset() {
        let config = test_config();
        let mut tracker = BudgetTracker::new(&config);

        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        tracker.record_usage(&usage);

        // Simulate a day boundary by pushing daily_start to yesterday
        if let Some(yesterday) =
            tracker.daily_start.checked_sub_signed(chrono::Duration::days(1))
        {
            tracker.daily_start = yesterday;
        }

        tracker.maybe_reset_daily();
        assert_eq!(tracker.status(Provider::OpenAI).daily_spent_cents, 0);
    }

    #[test]
    fn no_reset_same_day() {
        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        tracker.record_usage(&usage);

        let before = tracker.status(Provider::OpenAI).daily_spent_cents;
        tracker.maybe_reset_daily();
        let after = tracker.status(Provider::OpenAI).daily_spent_cents;

        assert_eq!(before, after);
    }

    #[test]
    fn multiple_providers_independent() {
        let mut tracker = BudgetTracker::new(&test_config());

        let openai_usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let anthropic_usage =
            make_usage(Provider::Anthropic, "claude-sonnet-4-6", 1_000_000, 0);

        tracker.record_usage(&openai_usage);
        tracker.record_usage(&anthropic_usage);

        let openai_status = tracker.status(Provider::OpenAI);
        let anthropic_status = tracker.status(Provider::Anthropic);

        assert_eq!(openai_status.session_spent_cents, 250);
        assert_eq!(anthropic_status.session_spent_cents, 300);
    }

    #[test]
    fn all_statuses_returns_all_providers() {
        let tracker = BudgetTracker::new(&test_config());
        let statuses = tracker.all_statuses();
        assert_eq!(statuses.len(), 3);

        let providers: Vec<Provider> = statuses.iter().map(|s| s.provider).collect();
        assert!(providers.contains(&Provider::OpenAI));
        assert!(providers.contains(&Provider::Anthropic));
        assert!(providers.contains(&Provider::Google));
    }

    #[test]
    fn save_load_roundtrip() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let path = dir.path().join("budget.json");

        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 500_000);
        tracker.record_usage(&usage);

        let anthropic_usage =
            make_usage(Provider::Anthropic, "claude-sonnet-4-6", 500_000, 200_000);
        tracker.record_usage(&anthropic_usage);

        // Save
        let save_result = tracker.save_to_file(&path);
        assert!(save_result.is_ok());

        // Load
        let loaded = BudgetTracker::load_from_file(&path, &test_config());
        assert!(loaded.is_ok());

        let Ok(loaded) = loaded else { return };

        // Verify spend was preserved
        assert_eq!(
            loaded.status(Provider::OpenAI).session_spent_cents,
            tracker.status(Provider::OpenAI).session_spent_cents
        );
        assert_eq!(
            loaded.status(Provider::Anthropic).session_spent_cents,
            tracker.status(Provider::Anthropic).session_spent_cents
        );
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = BudgetTracker::load_from_file(
            Path::new("/tmp/sanctum_nonexistent_budget_file_12345.json"),
            &test_config(),
        );
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn save_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let Ok(dir) = tempfile::tempdir() else { return };
        let path = dir.path().join("budget.json");

        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        tracker.record_usage(&usage);

        let save_result = tracker.save_to_file(&path);
        assert!(save_result.is_ok());

        let metadata = std::fs::metadata(&path);
        assert!(metadata.is_ok());
        let mode = metadata.map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
        assert_eq!(mode, 0o600, "budget file should have 0o600 permissions");
    }

    #[test]
    fn no_limits_configured() {
        let config = BudgetConfig {
            default_session: None,
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        let usage = make_usage(Provider::OpenAI, "gpt-4o", 10_000_000, 10_000_000);
        let status = tracker.record_usage(&usage);

        assert!(!status.session_exceeded);
        assert!(!status.daily_exceeded);
        assert!(!status.alert_triggered);
        assert!(status.session_limit_cents.is_none());
        assert!(status.daily_limit_cents.is_none());
    }

    #[test]
    fn u64_max_overflow_saturates() {
        let config = BudgetConfig {
            default_session: None,
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        // Pre-seed spend to just below u64::MAX so the next record_usage
        // triggers saturating_add overflow.
        tracker.session_spend.insert(Provider::OpenAI, u64::MAX - 1);
        tracker.daily_spend.insert(Provider::OpenAI, u64::MAX - 1);

        // Any non-zero usage will push past u64::MAX.
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        let status = tracker.record_usage(&usage);

        // Spend must saturate at u64::MAX, not wrap around to a small value.
        assert_eq!(
            status.session_spent_cents,
            u64::MAX,
            "session spend should saturate at u64::MAX"
        );
        assert_eq!(
            status.daily_spent_cents,
            u64::MAX,
            "daily spend should saturate at u64::MAX"
        );

        // A second record should remain pinned at u64::MAX.
        let status2 = tracker.record_usage(&usage);
        assert_eq!(status2.session_spent_cents, u64::MAX);
        assert_eq!(status2.daily_spent_cents, u64::MAX);
    }

    #[test]
    fn zero_budget_limit_immediately_exceeded() {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 0 }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        // Any usage at all should exceed a zero-cent session limit.
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1, 0);
        let status = tracker.record_usage(&usage);

        assert!(status.session_exceeded);
        assert_eq!(status.session_limit_cents, Some(0));
        assert!(status.session_spent_cents > 0);
    }

    #[test]
    fn year_boundary_daily_reset() {
        let config = test_config();
        let mut tracker = BudgetTracker::new(&config);

        // Record some usage so daily spend is non-zero.
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        tracker.record_usage(&usage);
        assert!(tracker.status(Provider::OpenAI).daily_spent_cents > 0);

        // Set daily_start to Dec 31 of a previous year.
        // `maybe_reset_daily()` compares ordinal and year, so crossing
        // into Jan 1 of the next year triggers a reset.
        tracker.daily_start = chrono::NaiveDate::from_ymd_opt(2024, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 0)
            .expect("valid time")
            .and_utc();

        tracker.maybe_reset_daily();

        // Daily counters should have been reset.
        assert_eq!(tracker.status(Provider::OpenAI).daily_spent_cents, 0);
    }

    #[test]
    fn save_to_file_no_temp_residue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("budget.json");

        let mut tracker = BudgetTracker::new(&test_config());
        let usage = make_usage(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        tracker.record_usage(&usage);

        tracker.save_to_file(&path).expect("save");

        // The final file must exist and be valid JSON
        let data = std::fs::read_to_string(&path).expect("read saved file");
        let _: serde_json::Value = serde_json::from_str(&data).expect("saved file must be valid JSON");

        // No .tmp residue should remain
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists(), "temp file should not remain after save");
    }

    #[test]
    fn corrupted_state_file_returns_err() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("budget.json");

        // Write invalid JSON.
        std::fs::write(&path, "this is not valid json {{{{").expect("write");

        let result = BudgetTracker::load_from_file(&path, &test_config());
        assert!(result.is_err(), "corrupted JSON should produce an error");
    }

    // ============================================================
    // PER-PROVIDER BUDGET OVERRIDES (W3)
    // ============================================================

    #[test]
    fn per_provider_limits_loaded_from_config() {
        use sanctum_types::config::ProviderBudgetConfig;

        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderBudgetConfig {
                session: Some(BudgetAmount { cents: 1000 }),
                daily: Some(BudgetAmount { cents: 5000 }),
                allowed_models: None,
            },
        );
        providers.insert(
            "anthropic".to_string(),
            ProviderBudgetConfig {
                session: Some(BudgetAmount { cents: 2000 }),
                daily: None,
                allowed_models: None,
            },
        );

        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 9999 }),
            default_daily: Some(BudgetAmount { cents: 50000 }),
            alert_at_percent: 75,
            providers,
        };

        let tracker = BudgetTracker::new(&config);

        // OpenAI should use its per-provider limits, not the defaults
        let openai_status = tracker.status(Provider::OpenAI);
        assert_eq!(openai_status.session_limit_cents, Some(1000));
        assert_eq!(openai_status.daily_limit_cents, Some(5000));

        // Anthropic should use per-provider session limit, default daily
        let anthropic_status = tracker.status(Provider::Anthropic);
        assert_eq!(anthropic_status.session_limit_cents, Some(2000));
        assert_eq!(anthropic_status.daily_limit_cents, Some(50000));

        // Google has no per-provider override, should use defaults
        let google_status = tracker.status(Provider::Google);
        assert_eq!(google_status.session_limit_cents, Some(9999));
        assert_eq!(google_status.daily_limit_cents, Some(50000));
    }

    #[test]
    fn per_provider_limits_survive_load_from_file() {
        use sanctum_types::config::ProviderBudgetConfig;

        let Ok(dir) = tempfile::tempdir() else { return };
        let path = dir.path().join("budget.json");

        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderBudgetConfig {
                session: Some(BudgetAmount { cents: 3000 }),
                daily: Some(BudgetAmount { cents: 10000 }),
                allowed_models: None,
            },
        );

        let config = BudgetConfig {
            default_session: Some(BudgetAmount { cents: 5000 }),
            default_daily: Some(BudgetAmount { cents: 20000 }),
            alert_at_percent: 75,
            providers,
        };

        let tracker = BudgetTracker::new(&config);
        let save_result = tracker.save_to_file(&path);
        assert!(save_result.is_ok());

        let loaded = BudgetTracker::load_from_file(&path, &config);
        assert!(loaded.is_ok());

        let Ok(loaded) = loaded else { return };
        let openai_status = loaded.status(Provider::OpenAI);
        assert_eq!(openai_status.session_limit_cents, Some(3000));
        assert_eq!(openai_status.daily_limit_cents, Some(10000));
    }
}
