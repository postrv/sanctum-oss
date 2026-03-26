//! Configuration types for Sanctum.
//!
//! All configuration is loaded from TOML files, validated at parse time,
//! and uses sensible defaults for omitted fields.

use serde::{Deserialize, Serialize};

/// Top-level Sanctum configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct SanctumConfig {
    /// Sentinel module configuration.
    pub sentinel: SentinelConfig,
    /// AI Firewall configuration.
    pub ai_firewall: AiFirewallConfig,
    /// Budget controller configuration.
    pub budgets: BudgetConfig,
}


/// How to respond when a suspicious `.pth` file is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PthResponse {
    /// Move the file to quarantine and replace with empty stub.
    Quarantine,
    /// Send a desktop notification but leave the file in place.
    Alert,
    /// Log the event silently.
    Log,
}

/// Sentinel module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    /// Whether to watch for `.pth` file modifications.
    pub watch_pth: bool,
    /// Whether to monitor credential file access.
    pub watch_credentials: bool,
    /// Whether to monitor for network anomalies (opt-in).
    pub watch_network: bool,
    /// How to respond to suspicious `.pth` files.
    pub pth_response: PthResponse,
    /// Known-safe `.pth` files by package name and content hash.
    pub pth_allowlist: Vec<PthAllowlistEntry>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            watch_pth: true,
            watch_credentials: true,
            watch_network: false,
            pth_response: PthResponse::Quarantine,
            pth_allowlist: Vec::new(),
        }
    }
}

/// An entry in the `.pth` allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PthAllowlistEntry {
    /// Package name (e.g., "setuptools").
    pub package: String,
    /// SHA-256 hash of the known-safe `.pth` content.
    pub hash: String,
}

/// AI Firewall configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiFirewallConfig {
    /// Whether to redact credentials from outbound prompts.
    pub redact_credentials: bool,
    /// Whether to install Claude Code hooks.
    pub claude_hooks: bool,
    /// Whether to audit MCP tool calls.
    pub mcp_audit: bool,
}

impl Default for AiFirewallConfig {
    fn default() -> Self {
        Self {
            redact_credentials: true,
            claude_hooks: true,
            mcp_audit: true,
        }
    }
}

/// Budget controller configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetConfig {
    /// Default per-session budget (e.g., "$50").
    pub default_session: Option<BudgetAmount>,
    /// Default per-day budget (e.g., "$200").
    pub default_daily: Option<BudgetAmount>,
    /// Percentage at which to send an alert notification.
    pub alert_at_percent: u8,
    /// Per-provider budget and model restrictions.
    pub providers: std::collections::HashMap<String, ProviderBudgetConfig>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            default_session: None,
            default_daily: None,
            alert_at_percent: 75,
            providers: std::collections::HashMap::new(),
        }
    }
}

/// Per-provider budget and model restrictions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderBudgetConfig {
    /// Per-session budget override for this provider.
    pub session: Option<BudgetAmount>,
    /// Per-day budget override for this provider.
    pub daily: Option<BudgetAmount>,
    /// Allowed model identifiers. If `None`, all models are allowed.
    /// If `Some(vec)`, only models in the list may be used.
    pub allowed_models: Option<Vec<String>>,
}

/// A monetary budget amount, parsed from strings like "$50" or "$200.00".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetAmount {
    /// Amount in cents to avoid floating-point issues.
    pub cents: u64,
}

impl<'de> Deserialize<'de> for BudgetAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim().trim_start_matches('$');
        if s.is_empty() {
            return Err(serde::de::Error::custom("empty budget amount"));
        }

        // Parse as float, then convert to cents
        let amount: f64 = s.parse().map_err(|_| {
            serde::de::Error::custom(format!("invalid budget format: {s}"))
        })?;

        if amount < 0.0 {
            return Err(serde::de::Error::custom("budget cannot be negative"));
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cents = (amount * 100.0).round() as u64;
        Ok(Self { cents })
    }
}

impl BudgetAmount {
    /// Return the budget as a dollar amount.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // cents values are small enough that f64 is exact
    pub fn dollars(&self) -> f64 {
        self.cents as f64 / 100.0
    }
}

impl std::fmt::Display for BudgetAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${:.2}", self.dollars())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn config_deserialises_from_minimal_toml() {
        let toml_str = r"
            [sentinel]
            watch_pth = true
        ";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("minimal config should parse");
        assert!(config.sentinel.watch_pth);
        assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);
    }

    #[test]
    fn config_rejects_invalid_budget_format() {
        let toml_str = r#"
            [budgets]
            default_session = "fifty dollars"
        "#;
        let result: Result<SanctumConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_negative_budget() {
        let toml_str = r#"
            [budgets]
            default_session = "$-50"
        "#;
        let result: Result<SanctumConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn budget_amount_parses_dollar_string() {
        let toml_str = r#"
            [budgets]
            default_session = "$50"
        "#;
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("dollar string should parse");
        let budget = config.budgets.default_session.expect("should have budget");
        assert_eq!(budget.cents, 5000);
        assert_eq!(budget.to_string(), "$50.00");
    }

    #[test]
    fn budget_amount_parses_decimal() {
        let toml_str = r#"
            [budgets]
            default_session = "$99.99"
        "#;
        let config: SanctumConfig = toml::from_str(toml_str).expect("decimal should parse");
        let budget = config.budgets.default_session.expect("should have budget");
        assert_eq!(budget.cents, 9999);
    }

    #[test]
    fn config_uses_defaults_for_omitted_fields() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert!(config.sentinel.watch_pth);
        assert!(!config.sentinel.watch_network);
        assert_eq!(config.budgets.alert_at_percent, 75);
    }
}
