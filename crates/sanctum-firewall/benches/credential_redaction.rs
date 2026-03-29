#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanctum_firewall::redaction::redact_credentials;

fn make_clean_text(size: usize) -> String {
    // Repeating prose that contains no credential patterns
    let base = "The quick brown fox jumps over the lazy dog. ";
    base.repeat(size / base.len() + 1)[..size].to_string()
}

fn make_text_with_credential(size: usize) -> String {
    let prefix_len = size / 2;
    let prefix = make_clean_text(prefix_len);
    let credential = "sk-abcdefghijklmnopqrstuvwxyz";
    let suffix_len = size.saturating_sub(prefix_len + credential.len());
    let suffix = make_clean_text(suffix_len);
    format!("{prefix}{credential}{suffix}")
}

fn make_text_with_multiple_credentials(size: usize) -> String {
    let chunk = size / 5;
    let parts = [
        make_clean_text(chunk),
        "sk-abcdefghijklmnopqrstuvwxyz".to_string(),
        make_clean_text(chunk),
        "AKIAIOSFODNN7EXAMPLE".to_string(),
        make_clean_text(chunk),
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".to_string(),
        make_clean_text(chunk),
    ];
    let result = parts.join(" ");
    result[..size.min(result.len())].to_string()
}

fn bench_redact_small_clean(c: &mut Criterion) {
    let input = make_clean_text(100);
    c.bench_function("redact_credentials/100B_clean", |b| {
        b.iter(|| redact_credentials(black_box(&input)));
    });
}

fn bench_redact_medium_one_credential(c: &mut Criterion) {
    let input = make_text_with_credential(1024);
    c.bench_function("redact_credentials/1KB_one_credential", |b| {
        b.iter(|| redact_credentials(black_box(&input)));
    });
}

fn bench_redact_large_multiple_credentials(c: &mut Criterion) {
    let input = make_text_with_multiple_credentials(10 * 1024);
    c.bench_function("redact_credentials/10KB_multiple_credentials", |b| {
        b.iter(|| redact_credentials(black_box(&input)));
    });
}

fn bench_redact_medium_clean(c: &mut Criterion) {
    let input = make_clean_text(1024);
    c.bench_function("redact_credentials/1KB_clean", |b| {
        b.iter(|| redact_credentials(black_box(&input)));
    });
}

fn bench_redact_large_clean(c: &mut Criterion) {
    let input = make_clean_text(10 * 1024);
    c.bench_function("redact_credentials/10KB_clean", |b| {
        b.iter(|| redact_credentials(black_box(&input)));
    });
}

criterion_group!(
    benches,
    bench_redact_small_clean,
    bench_redact_medium_clean,
    bench_redact_medium_one_credential,
    bench_redact_large_clean,
    bench_redact_large_multiple_credentials,
);
criterion_main!(benches);
