#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanctum_firewall::mcp::policy::{McpPolicy, PolicyRule};
use sanctum_types::config::McpDefaultPolicy;
use serde_json::json;

fn make_policy_with_rules() -> McpPolicy {
    McpPolicy::from_config(vec![
        PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec![
                "/home/user/.ssh/**".to_owned(),
                "/home/user/.aws/**".to_owned(),
            ],
        },
        PolicyRule {
            tool: "write_file".to_owned(),
            restricted_paths: vec!["/etc/**".to_owned(), "**/*.pth".to_owned()],
        },
        PolicyRule {
            tool: "exec".to_owned(),
            restricted_paths: vec!["/usr/bin/**".to_owned()],
        },
    ])
}

fn bench_evaluate_allow_no_rules(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"path": "/home/user/project/src/main.rs"});

    c.bench_function("mcp_policy/evaluate_allow_empty_rules", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_allow_with_rules(c: &mut Criterion) {
    let policy = make_policy_with_rules();
    let args = json!({"path": "/home/user/project/src/main.rs"});

    c.bench_function("mcp_policy/evaluate_allow_with_rules", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_block_user_rule(c: &mut Criterion) {
    let policy = make_policy_with_rules();
    let args = json!({"path": "/home/user/.ssh/id_rsa"});

    c.bench_function("mcp_policy/evaluate_block_user_rule", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_block_builtin_ssh(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"file_path": "/home/user/.ssh/id_rsa"});

    c.bench_function("mcp_policy/evaluate_block_builtin_ssh", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("any_tool"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_block_builtin_env(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"file_path": "/home/user/project/.env.production"});

    c.bench_function("mcp_policy/evaluate_block_builtin_env", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("write_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_block_builtin_aws(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"path": "/home/user/.aws/credentials"});

    c.bench_function("mcp_policy/evaluate_block_builtin_aws", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_safe_path_not_sensitive(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"file_path": "/home/user/projects/app/src/lib.rs"});

    c.bench_function("mcp_policy/evaluate_safe_non_sensitive_path", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_nested_json_args(c: &mut Criterion) {
    let policy = make_policy_with_rules();
    let args = json!({
        "operation": "read",
        "options": {
            "file": "/home/user/project/data.json",
            "encoding": "utf-8"
        },
        "metadata": {
            "tags": ["safe", "/home/user/.ssh/id_rsa"]
        }
    });

    c.bench_function("mcp_policy/evaluate_nested_json_args", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("read_file"),
                black_box(&args),
                McpDefaultPolicy::Allow,
            )
        });
    });
}

fn bench_evaluate_default_deny(c: &mut Criterion) {
    let policy = McpPolicy::from_config(vec![]);
    let args = json!({"path": "/home/user/project/src/main.rs"});

    c.bench_function("mcp_policy/evaluate_default_deny", |b| {
        b.iter(|| {
            policy.evaluate(
                black_box("unknown_tool"),
                black_box(&args),
                McpDefaultPolicy::Deny,
            )
        });
    });
}

criterion_group!(
    benches,
    bench_evaluate_allow_no_rules,
    bench_evaluate_allow_with_rules,
    bench_evaluate_block_user_rule,
    bench_evaluate_block_builtin_ssh,
    bench_evaluate_block_builtin_env,
    bench_evaluate_block_builtin_aws,
    bench_evaluate_safe_path_not_sensitive,
    bench_evaluate_nested_json_args,
    bench_evaluate_default_deny,
);
criterion_main!(benches);
