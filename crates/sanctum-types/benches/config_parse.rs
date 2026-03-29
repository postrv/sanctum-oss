#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanctum_types::config::SanctumConfig;

const MINIMAL_CONFIG: &str = r"
[sentinel]
watch_pth = true
";

const FULL_CONFIG: &str = r#"
config_version = 1

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = true
pth_response = "quarantine"
credential_allowlist = ["/usr/bin/git", "/usr/bin/ssh"]

[sentinel.network]
poll_interval_secs = 10
transfer_threshold_bytes = 50000000
process_allowlist = ["Dropbox", "rsync", "rclone"]
destination_blocklist = ["10.0.0.1"]
safe_ports = [80, 443, 22, 53, 8080]

[[sentinel.pth_allowlist]]
package = "setuptools"
hash = "sha256:87562230a1af758c6c9cafecbd52ccd5b81951c3aa8101d5aa843586bf51ff51"

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true
default_mcp_policy = "warn"

[[ai_firewall.mcp_rules]]
tool = "read_file"
restricted_paths = ["/home/user/.ssh/**", "/home/user/.aws/**"]

[[ai_firewall.mcp_rules]]
tool = "write_file"
restricted_paths = ["**/*.pth"]

[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 80

[budgets.providers.anthropic]
session = "$25"
daily = "$100"
allowed_models = ["claude-sonnet-4-20250514"]

[proxy]
enabled = true
listen_port = 9847
enforce_budget = true
enforce_allowed_models = true
ca_validity_days = 365
max_response_body_bytes = 10485760
"#;

fn bench_parse_empty_config(c: &mut Criterion) {
    c.bench_function("config_parse/empty_defaults", |b| {
        b.iter(|| {
            let _config: SanctumConfig = toml::from_str(black_box("")).unwrap();
        });
    });
}

fn bench_parse_minimal_config(c: &mut Criterion) {
    c.bench_function("config_parse/minimal", |b| {
        b.iter(|| {
            let _config: SanctumConfig = toml::from_str(black_box(MINIMAL_CONFIG)).unwrap();
        });
    });
}

fn bench_parse_full_config(c: &mut Criterion) {
    c.bench_function("config_parse/full", |b| {
        b.iter(|| {
            let _config: SanctumConfig = toml::from_str(black_box(FULL_CONFIG)).unwrap();
        });
    });
}

fn bench_serialize_default_config(c: &mut Criterion) {
    let config = SanctumConfig::default();
    c.bench_function("config_serialize/default", |b| {
        b.iter(|| {
            let _toml = toml::to_string(black_box(&config)).unwrap();
        });
    });
}

fn bench_parse_roundtrip(c: &mut Criterion) {
    c.bench_function("config_parse/roundtrip", |b| {
        b.iter(|| {
            let config: SanctumConfig = toml::from_str(black_box(FULL_CONFIG)).unwrap();
            let serialized = toml::to_string(&config).unwrap();
            let _roundtripped: SanctumConfig = toml::from_str(&serialized).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_parse_empty_config,
    bench_parse_minimal_config,
    bench_parse_full_config,
    bench_serialize_default_config,
    bench_parse_roundtrip,
);
criterion_main!(benches);
