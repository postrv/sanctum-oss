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
    /// Configuration file version for forward compatibility.
    #[serde(default)]
    pub config_version: Option<u32>,
    /// Sentinel module configuration.
    pub sentinel: SentinelConfig,
    /// AI Firewall configuration.
    pub ai_firewall: AiFirewallConfig,
    /// Budget controller configuration.
    pub budgets: BudgetConfig,
    /// HTTP Budget Proxy configuration.
    pub proxy: ProxyConfig,
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
#[allow(clippy::struct_excessive_bools)]
pub struct SentinelConfig {
    /// Whether to watch for `.pth` file modifications.
    pub watch_pth: bool,
    /// Whether to monitor credential file access.
    pub watch_credentials: bool,
    /// Whether to monitor for network anomalies (opt-in).
    pub watch_network: bool,
    /// Whether to monitor npm `node_modules` for malicious lifecycle scripts.
    pub watch_npm: bool,
    /// How to respond to suspicious `.pth` files.
    pub pth_response: PthResponse,
    /// Known-safe `.pth` files by package name and content hash.
    pub pth_allowlist: Vec<PthAllowlistEntry>,
    /// Executables allowed to access credential files without triggering alerts.
    pub credential_allowlist: Vec<String>,
    /// Network monitoring configuration.
    pub network: NetworkConfig,
    /// npm ecosystem monitoring settings.
    #[serde(default)]
    pub npm: NpmConfig,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            watch_pth: true,
            watch_credentials: true,
            watch_network: false,
            watch_npm: false,
            pth_response: PthResponse::Quarantine,
            pth_allowlist: Vec::new(),
            credential_allowlist: Vec::new(),
            network: NetworkConfig::default(),
            npm: NpmConfig::default(),
        }
    }
}

/// Serde default helper that returns `true`.
const fn default_true() -> bool {
    true
}

/// Configuration for npm ecosystem monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NpmConfig {
    /// Monitor npm lifecycle scripts during install.
    #[serde(default = "default_true")]
    pub watch_lifecycle: bool,

    /// Warn when npm install is used without `--ignore-scripts`.
    #[serde(default = "default_true")]
    pub ignore_scripts_warning: bool,

    /// Packages whose lifecycle scripts should be allowed without alerts.
    #[serde(default = "default_npm_allowlist")]
    pub allowlist: Vec<String>,

    /// Project directories containing `node_modules` to monitor.
    #[serde(default)]
    pub project_dirs: Vec<String>,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            watch_lifecycle: true,
            ignore_scripts_warning: true,
            allowlist: default_npm_allowlist(),
            project_dirs: Vec::new(),
        }
    }
}

/// Default allowlist of npm packages whose lifecycle scripts are considered safe.
#[must_use]
pub fn default_npm_allowlist() -> Vec<String> {
    vec![
        "esbuild".to_owned(),
        "electron".to_owned(),
        "sharp".to_owned(),
        "node-sass".to_owned(),
        "fsevents".to_owned(),
        "grpc-tools".to_owned(),
        "sqlite3".to_owned(),
        "better-sqlite3".to_owned(),
        "bcrypt".to_owned(),
        "canvas".to_owned(),
        "cpu-features".to_owned(),
        "sodium-native".to_owned(),
        "swc".to_owned(),
        "@swc/core".to_owned(),
        "puppeteer".to_owned(),
        "playwright".to_owned(),
        "turbo".to_owned(),
        "prisma".to_owned(),
        "@prisma/client".to_owned(),
        "@prisma/engines".to_owned(),
        "protobufjs".to_owned(),
    ]
}

/// Deserialise `alert_at_percent`, clamping to a maximum of 100.
fn deserialize_alert_at_percent<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    Ok(value.min(100))
}

/// Deserialise a poll interval, clamping to 1..=3600.
/// `tokio::time::interval(Duration::ZERO)` panics, so we enforce a minimum of 1.
/// Values above 3600 (1 hour) effectively disable monitoring, so we cap there.
fn deserialize_poll_interval<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    Ok(value.clamp(1, 3600))
}

/// Network monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Polling interval in seconds (clamped to 1..=3600).
    #[serde(deserialize_with = "deserialize_poll_interval")]
    pub poll_interval_secs: u64,
    /// Baseline learning period in days.
    pub learning_period_days: u32,
    /// Outbound transfer alert threshold in bytes per hour.
    pub transfer_threshold_bytes: u64,
    /// Processes to exclude from monitoring.
    pub process_allowlist: Vec<String>,
    /// Known-safe destination IP addresses (CIDR ranges are not currently supported).
    pub destination_allowlist: Vec<String>,
    /// Known-bad destination IP addresses (CIDR ranges are not currently supported).
    pub destination_blocklist: Vec<String>,
    /// Ports that should never trigger "unusual port" alerts.
    pub safe_ports: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
            learning_period_days: 7,
            transfer_threshold_bytes: 100 * 1024 * 1024,
            process_allowlist: vec![
                "Dropbox".to_owned(),
                "rsync".to_owned(),
                "rclone".to_owned(),
                "TimeMachine".to_owned(),
                "backupd".to_owned(),
            ],
            destination_allowlist: Vec::new(),
            destination_blocklist: Vec::new(),
            safe_ports: vec![80, 443, 22, 53, 8080, 8443, 3000, 5000, 5432, 3306, 6379],
        }
    }
}

/// Deserialise `ca_validity_days`, clamping to 1..=3650.
fn deserialize_ca_validity_days<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    Ok(value.clamp(1, 3650))
}

/// Deserialise `max_response_body_bytes`, clamping to 1..=100MB.
fn deserialize_max_response_body_bytes<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = usize::deserialize(deserializer)?;
    Ok(value.clamp(1, 100 * 1024 * 1024)) // 1 byte to 100MB
}

/// An entry in the `.pth` allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PthAllowlistEntry {
    /// Package name (e.g., "setuptools").
    pub package: String,
    /// SHA-256 hash of the known-safe `.pth` content.
    pub hash: String,
}

/// Default policy for MCP tools that do not match any explicit rule.
///
/// Controls what happens when an MCP tool invocation has no matching
/// policy rule. `Allow` preserves backwards-compatible behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpDefaultPolicy {
    /// Allow unmatched MCP tools (backwards-compatible default).
    #[default]
    Allow,
    /// Allow but emit a warning for unmatched MCP tools.
    Warn,
    /// Block unmatched MCP tools entirely.
    Deny,
}

/// Configuration for a single MCP policy rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpPolicyRuleConfig {
    /// The MCP tool name this rule applies to.
    pub tool: String,
    /// Glob patterns for paths that are restricted for this tool.
    pub restricted_paths: Vec<String>,
}

/// AI Firewall configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct AiFirewallConfig {
    /// Whether to redact credentials from outbound prompts.
    pub redact_credentials: bool,
    /// Whether to install Claude Code hooks.
    pub claude_hooks: bool,
    /// Whether to audit MCP tool calls.
    pub mcp_audit: bool,
    /// Enable slopsquatting detection (registry existence check before install).
    #[serde(default = "default_true")]
    pub check_package_existence: bool,
    /// Timeout in milliseconds for package registry lookups (fail-open).
    #[serde(default = "default_package_check_timeout")]
    pub package_check_timeout_ms: u64,
    /// MCP tool policy rules. Each rule restricts specific tools from accessing certain paths.
    pub mcp_rules: Vec<McpPolicyRuleConfig>,
    /// Default policy for MCP tools that do not match any explicit rule.
    #[serde(default)]
    pub default_mcp_policy: McpDefaultPolicy,
}

/// Default timeout for package registry lookups (3 seconds).
const fn default_package_check_timeout() -> u64 {
    3000
}

impl Default for AiFirewallConfig {
    fn default() -> Self {
        Self {
            redact_credentials: true,
            claude_hooks: true,
            mcp_audit: true,
            check_package_existence: true,
            package_check_timeout_ms: default_package_check_timeout(),
            mcp_rules: Vec::new(),
            default_mcp_policy: McpDefaultPolicy::Allow,
        }
    }
}

/// HTTP Budget Proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Whether the proxy is enabled.
    pub enabled: bool,
    /// Listen port (binds to 127.0.0.1 only).
    pub listen_port: u16,
    /// Whether to block requests when budget is exceeded.
    pub enforce_budget: bool,
    /// Whether to enforce model allowlists.
    pub enforce_allowed_models: bool,
    /// CA certificate validity in days (clamped to 1..=3650).
    #[serde(deserialize_with = "deserialize_ca_validity_days")]
    pub ca_validity_days: u32,
    /// Maximum response body size to buffer for usage extraction (bytes, clamped to 1..=100MB).
    #[serde(deserialize_with = "deserialize_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 9847,
            enforce_budget: true,
            enforce_allowed_models: true,
            ca_validity_days: 365,
            max_response_body_bytes: 10 * 1024 * 1024, // 10 MB
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
    /// Percentage at which to send an alert notification (clamped to 0..=100).
    #[serde(deserialize_with = "deserialize_alert_at_percent")]
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
        let amount: f64 = s
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("invalid budget format: {s}")))?;

        if !amount.is_finite() {
            return Err(serde::de::Error::custom("budget must be a finite number"));
        }

        if amount < 0.0 {
            return Err(serde::de::Error::custom("budget cannot be negative"));
        }

        let cents_f = (amount * 100.0).round();
        // u64::MAX as f64 rounds up to 2^64, so any cents_f at or above
        // that value would overflow the u64 cast.
        #[allow(clippy::cast_precision_loss)]
        if cents_f >= u64::MAX as f64 {
            return Err(serde::de::Error::custom("budget amount too large"));
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cents = cents_f as u64;
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
        let config: SanctumConfig = toml::from_str(toml_str).expect("minimal config should parse");
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
        let config: SanctumConfig = toml::from_str(toml_str).expect("dollar string should parse");
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

    #[test]
    fn config_version_defaults_to_none() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert!(config.config_version.is_none());
    }

    #[test]
    fn config_version_parses_from_toml() {
        let toml_str = "config_version = 1\n";
        let config: SanctumConfig = toml::from_str(toml_str).expect("config_version should parse");
        assert_eq!(config.config_version, Some(1));
    }

    #[test]
    fn credential_allowlist_deserialises_from_toml() {
        let toml_str = r#"
            [sentinel]
            watch_pth = true
            credential_allowlist = ["/usr/bin/git", "/usr/bin/ssh"]
        "#;
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("credential_allowlist config should parse");
        assert_eq!(config.sentinel.credential_allowlist.len(), 2);
        assert_eq!(config.sentinel.credential_allowlist[0], "/usr/bin/git");
        assert_eq!(config.sentinel.credential_allowlist[1], "/usr/bin/ssh");
    }

    #[test]
    fn credential_allowlist_defaults_to_empty() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert!(config.sentinel.credential_allowlist.is_empty());
    }

    #[test]
    fn network_config_defaults_are_correct() {
        let config = NetworkConfig::default();
        assert_eq!(config.poll_interval_secs, 30);
        assert_eq!(config.learning_period_days, 7);
        assert_eq!(config.transfer_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(config.process_allowlist.len(), 5);
        assert!(config.process_allowlist.contains(&"Dropbox".to_owned()));
        assert!(config.destination_allowlist.is_empty());
        assert!(config.destination_blocklist.is_empty());
        assert_eq!(config.safe_ports.len(), 11);
        assert!(config.safe_ports.contains(&443));
        assert!(config.safe_ports.contains(&22));
    }

    #[test]
    fn network_config_deserialises_from_toml() {
        let toml_str = r#"
            [sentinel.network]
            poll_interval_secs = 10
            learning_period_days = 14
            transfer_threshold_bytes = 50000000
            process_allowlist = ["myapp"]
            destination_blocklist = ["10.0.0.1"]
            safe_ports = [80, 443]
        "#;
        let config: SanctumConfig = toml::from_str(toml_str).expect("network config should parse");
        assert_eq!(config.sentinel.network.poll_interval_secs, 10);
        assert_eq!(config.sentinel.network.learning_period_days, 14);
        assert_eq!(config.sentinel.network.transfer_threshold_bytes, 50_000_000);
        assert_eq!(config.sentinel.network.process_allowlist, vec!["myapp"]);
        assert_eq!(
            config.sentinel.network.destination_blocklist,
            vec!["10.0.0.1"]
        );
        assert_eq!(config.sentinel.network.safe_ports, vec![80, 443]);
    }

    #[test]
    fn network_config_uses_defaults_when_omitted() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert_eq!(config.sentinel.network.poll_interval_secs, 30);
        assert!(!config.sentinel.network.safe_ports.is_empty());
    }

    #[test]
    fn test_mcp_rules_default_empty() {
        assert!(AiFirewallConfig::default().mcp_rules.is_empty());
    }

    #[test]
    fn test_default_mcp_policy_defaults_to_allow() {
        let config = AiFirewallConfig::default();
        assert_eq!(config.default_mcp_policy, McpDefaultPolicy::Allow);
    }

    #[test]
    fn test_default_mcp_policy_omitted_is_allow() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Allow
        );
    }

    #[test]
    fn test_default_mcp_policy_warn_deserialises() {
        let toml_str = r#"
            [ai_firewall]
            default_mcp_policy = "warn"
        "#;
        let config: SanctumConfig = toml::from_str(toml_str).expect("warn policy should parse");
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Warn
        );
    }

    #[test]
    fn test_default_mcp_policy_deny_deserialises() {
        let toml_str = r#"
            [ai_firewall]
            default_mcp_policy = "deny"
        "#;
        let config: SanctumConfig = toml::from_str(toml_str).expect("deny policy should parse");
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Deny
        );
    }

    #[test]
    fn test_mcp_rules_deserialize() {
        let toml_str = r#"
            [ai_firewall]
            redact_credentials = true

            [[ai_firewall.mcp_rules]]
            tool = "read_file"
            restricted_paths = ["/home/user/.ssh/**", "/home/user/.aws/**"]

            [[ai_firewall.mcp_rules]]
            tool = "write_file"
            restricted_paths = ["**/*.pth"]
        "#;
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("mcp_rules config should parse");
        assert_eq!(config.ai_firewall.mcp_rules.len(), 2);

        let rule0 = &config.ai_firewall.mcp_rules[0];
        assert_eq!(rule0.tool, "read_file");
        assert_eq!(rule0.restricted_paths.len(), 2);
        assert_eq!(rule0.restricted_paths[0], "/home/user/.ssh/**");
        assert_eq!(rule0.restricted_paths[1], "/home/user/.aws/**");

        let rule1 = &config.ai_firewall.mcp_rules[1];
        assert_eq!(rule1.tool, "write_file");
        assert_eq!(rule1.restricted_paths.len(), 1);
        assert_eq!(rule1.restricted_paths[0], "**/*.pth");
    }

    #[test]
    fn proxy_config_defaults_are_correct() {
        let config = ProxyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.listen_port, 9847);
        assert!(config.enforce_budget);
        assert!(config.enforce_allowed_models);
        assert_eq!(config.ca_validity_days, 365);
        assert_eq!(config.max_response_body_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn proxy_config_deserialises_from_toml() {
        let toml_str = r"
            [proxy]
            enabled = true
            listen_port = 8080
            enforce_budget = false
            enforce_allowed_models = false
            ca_validity_days = 30
            max_response_body_bytes = 5242880
        ";
        let config: SanctumConfig = toml::from_str(toml_str).expect("proxy config should parse");
        assert!(config.proxy.enabled);
        assert_eq!(config.proxy.listen_port, 8080);
        assert!(!config.proxy.enforce_budget);
        assert!(!config.proxy.enforce_allowed_models);
        assert_eq!(config.proxy.ca_validity_days, 30);
        assert_eq!(config.proxy.max_response_body_bytes, 5_242_880);
    }

    #[test]
    fn proxy_config_uses_defaults_when_omitted() {
        let toml_str = "";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("empty config should use defaults");
        assert!(!config.proxy.enabled);
        assert_eq!(config.proxy.listen_port, 9847);
        assert!(config.proxy.enforce_budget);
    }

    #[test]
    fn budget_rejects_infinity() {
        let toml_str = r#"
            [budgets]
            default_session = "$inf"
        "#;
        let result: Result<SanctumConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "infinity should be rejected");
    }

    #[test]
    fn budget_rejects_nan() {
        let toml_str = r#"
            [budgets]
            default_session = "$NaN"
        "#;
        let result: Result<SanctumConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "NaN should be rejected");
    }

    #[test]
    fn budget_rejects_overflow() {
        let toml_str = r#"
            [budgets]
            default_session = "$184467440737095517.00"
        "#;
        let result: Result<SanctumConfig, _> = toml::from_str(toml_str);
        assert!(
            result.is_err(),
            "amount that overflows u64 cents should be rejected"
        );
    }

    #[test]
    fn ca_validity_days_clamped_to_bounds() {
        let toml_str = "[proxy]\nca_validity_days = 0\n";
        let config: SanctumConfig = toml::from_str(toml_str).expect("valid toml");
        assert_eq!(config.proxy.ca_validity_days, 1);

        let toml_str = "[proxy]\nca_validity_days = 999999\n";
        let config: SanctumConfig = toml::from_str(toml_str).expect("valid toml");
        assert_eq!(config.proxy.ca_validity_days, 3650);
    }

    #[test]
    fn max_response_body_bytes_clamped() {
        let toml_str = "[proxy]\nmax_response_body_bytes = 0\n";
        let config: SanctumConfig = toml::from_str(toml_str).expect("valid toml");
        assert_eq!(config.proxy.max_response_body_bytes, 1);
    }

    #[test]
    fn alert_at_percent_clamped_to_100() {
        let toml_str = r"
            [budgets]
            alert_at_percent = 200
        ";
        let config: SanctumConfig = toml::from_str(toml_str).expect("config should parse");
        assert_eq!(
            config.budgets.alert_at_percent, 100,
            "alert_at_percent > 100 should be clamped to 100"
        );
    }

    #[test]
    fn poll_interval_zero_clamped_to_minimum() {
        let toml_str = r"
            [sentinel]
            watch_network = true

            [sentinel.network]
            poll_interval_secs = 0
        ";
        let config: SanctumConfig = toml::from_str(toml_str).expect("config should parse");
        // Zero interval would panic tokio — must be clamped to at least 1
        assert!(
            config.sentinel.network.poll_interval_secs >= 1,
            "poll_interval_secs must be at least 1 to avoid tokio panic"
        );
    }

    #[test]
    fn poll_interval_clamped_to_upper_bound() {
        let toml_str = r"
            [sentinel.network]
            poll_interval_secs = 86400
        ";
        let config: SanctumConfig = toml::from_str(toml_str).expect("config should parse");
        assert_eq!(
            config.sentinel.network.poll_interval_secs, 3600,
            "poll_interval_secs above 3600 should be clamped to 3600"
        );
    }

    #[test]
    fn npm_config_default() {
        let npm = NpmConfig::default();
        assert!(npm.watch_lifecycle);
        assert!(npm.ignore_scripts_warning);
        assert!(!npm.allowlist.is_empty());
        assert!(npm.project_dirs.is_empty());
    }

    #[test]
    fn config_without_npm_section_deserializes() {
        let toml_str = r"
            [sentinel]
            watch_pth = true
        ";
        let config: SanctumConfig =
            toml::from_str(toml_str).expect("config without npm should parse");
        // npm should have defaults when section is absent
        assert!(config.sentinel.npm.watch_lifecycle);
    }

    #[test]
    fn config_with_npm_section_deserializes() {
        let toml_str = r"
            [sentinel.npm]
            watch_lifecycle = false
            ignore_scripts_warning = true
        ";
        let config: SanctumConfig = toml::from_str(toml_str).expect("config with npm should parse");
        assert!(!config.sentinel.npm.watch_lifecycle);
        assert!(config.sentinel.npm.ignore_scripts_warning);
    }

    #[test]
    fn npm_config_serializes_correctly() {
        let npm = NpmConfig::default();
        let toml_str = toml::to_string(&npm).expect("should serialize");
        assert!(toml_str.contains("watch_lifecycle = true"));
        assert!(toml_str.contains("ignore_scripts_warning = true"));
    }

    #[test]
    fn npm_allowlist_has_expected_packages() {
        let allowlist = default_npm_allowlist();
        assert!(allowlist.contains(&"esbuild".to_owned()));
        assert!(allowlist.contains(&"puppeteer".to_owned()));
        assert!(allowlist.contains(&"sharp".to_owned()));
    }
}
