//! Package-manager policy parsing, validation, and registry checking.
//!
//! This module is deliberately independent from the Claude hook surface so the
//! ecosystem parsers and registry checker can be unit-tested without live
//! network access.

#[cfg(not(test))]
use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;

/// Npm/JS package manager configuration for hook behaviour.
#[derive(Debug, Clone)]
pub struct NpmConfig {
    /// Whether to warn about npm lifecycle script risks in post-bash.
    pub watch_lifecycle: bool,
    /// Whether to suggest `--ignore-scripts` in pre-bash npm install warnings.
    pub ignore_scripts_warning: bool,
    /// Whether to BLOCK npm/yarn/pnpm/bun install commands that lack `--ignore-scripts`.
    pub ignore_scripts_required: bool,
    /// Package names that skip slopsquatting checks (known-good packages).
    pub allowlist: Vec<String>,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            watch_lifecycle: true,
            ignore_scripts_warning: true,
            ignore_scripts_required: false,
            allowlist: Vec::new(),
        }
    }
}

/// Go module ecosystem configuration for hook behaviour.
#[derive(Debug, Clone)]
pub struct GoConfig {
    /// Module paths that skip slopsquatting checks (exact match).
    pub allowlist: Vec<String>,
    /// Trusted module path prefixes that skip checks.
    pub trusted_prefixes: Vec<String>,
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            trusted_prefixes: default_go_trusted_prefixes(),
        }
    }
}

/// Default trusted Go module path prefixes.
#[must_use]
pub fn default_go_trusted_prefixes() -> Vec<String> {
    vec![
        "golang.org/x/".to_owned(),
        "google.golang.org/".to_owned(),
        "cloud.google.com/go/".to_owned(),
        "github.com/golang/".to_owned(),
    ]
}

/// Rust/Cargo ecosystem configuration for hook behaviour.
#[derive(Debug, Clone)]
pub struct CargoConfig {
    /// Crate names that skip slopsquatting checks (exact match).
    pub allowlist: Vec<String>,
    /// Warn when cargo downloads new crates (build.rs may execute).
    pub warn_build_scripts: bool,
}

impl Default for CargoConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            warn_build_scripts: true,
        }
    }
}

/// Python/pip ecosystem configuration for hook behaviour.
#[derive(Debug, Clone)]
pub struct PipConfig {
    /// Package names that skip slopsquatting checks (exact match).
    pub allowlist: Vec<String>,
    /// Warn when pip install runs without `--only-binary :all:`.
    pub warn_source_installs: bool,
    /// Block pip install commands without `--only-binary :all:`.
    pub require_binary_only: bool,
}

impl Default for PipConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            warn_source_installs: true,
            require_binary_only: false,
        }
    }
}

/// Homebrew ecosystem configuration for hook behaviour.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct HomebrewConfig {
    /// Formula or cask names that skip official Homebrew API existence checks.
    pub allowlist: Vec<String>,
    /// Taps considered trusted for tap-qualified package installs.
    pub trusted_taps: Vec<String>,
    /// Warn when commands reference untrusted taps.
    pub warn_untrusted_taps: bool,
    /// Warn when cask quarantine is bypassed.
    pub warn_no_quarantine: bool,
    /// Block direct installs from URL/path formula files.
    pub block_external_formula_installs: bool,
    /// Warn when `brew bundle` reads a Brewfile.
    pub warn_brewfile: bool,
}

impl Default for HomebrewConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            trusted_taps: vec![
                "homebrew/core".to_owned(),
                "homebrew/cask".to_owned(),
                "homebrew/services".to_owned(),
                "homebrew/bundle".to_owned(),
            ],
            warn_untrusted_taps: true,
            warn_no_quarantine: true,
            block_external_formula_installs: true,
            warn_brewfile: true,
        }
    }
}

/// Docker image safety configuration for hook behaviour.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// Docker registries considered trusted.
    pub trusted_registries: Vec<String>,
    /// Warn on `:latest` or untagged images.
    pub warn_latest: bool,
    /// Warn on `ADD` with remote URLs in Dockerfiles.
    pub warn_remote_add: bool,
    /// Warn on `curl|sh` / `wget|bash` patterns in Dockerfile `RUN`.
    pub warn_pipe_install: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            trusted_registries: vec![
                "docker.io".to_owned(),
                "ghcr.io".to_owned(),
                "gcr.io".to_owned(),
                "public.ecr.aws".to_owned(),
                "registry.k8s.io".to_owned(),
            ],
            warn_latest: true,
            warn_remote_add: true,
            warn_pipe_install: true,
        }
    }
}

/// NuGet/.NET ecosystem configuration.
#[derive(Debug, Clone)]
pub struct NugetConfig {
    /// `NuGet` package IDs that skip registry checks.
    pub allowlist: Vec<String>,
    /// Package sources considered trusted.
    pub trusted_sources: Vec<String>,
    /// Warn when dotnet/msbuild commands may implicitly restore packages.
    pub warn_implicit_restore: bool,
}

impl Default for NugetConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            trusted_sources: vec!["https://api.nuget.org/v3/index.json".to_owned()],
            warn_implicit_restore: true,
        }
    }
}

/// Maven ecosystem configuration.
#[derive(Debug, Clone)]
pub struct MavenConfig {
    /// Maven coordinates in `groupId:artifactId` form that skip checks.
    pub allowlist: Vec<String>,
    /// Trusted groupId prefixes that skip checks.
    pub trusted_prefixes: Vec<String>,
    /// Warn when Maven wrappers or repository declarations may download code.
    pub warn_wrapper_download: bool,
}

impl Default for MavenConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            trusted_prefixes: default_java_trusted_prefixes(),
            warn_wrapper_download: true,
        }
    }
}

/// Gradle ecosystem configuration.
#[derive(Debug, Clone)]
pub struct GradleConfig {
    /// Gradle coordinates/plugin IDs that skip checks.
    pub allowlist: Vec<String>,
    /// Trusted group/plugin prefixes that skip checks.
    pub trusted_prefixes: Vec<String>,
    /// Warn when dynamic dependency versions are used.
    pub warn_dynamic_versions: bool,
}

impl Default for GradleConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            trusted_prefixes: default_java_trusted_prefixes(),
            warn_dynamic_versions: true,
        }
    }
}

/// Default trusted Java ecosystem prefixes.
#[must_use]
pub fn default_java_trusted_prefixes() -> Vec<String> {
    vec![
        "org.apache.".to_owned(),
        "com.google.".to_owned(),
        "org.springframework.".to_owned(),
        "org.jetbrains.".to_owned(),
        "io.micrometer.".to_owned(),
    ]
}

/// Bundle of per-ecosystem package manager configurations.
#[derive(Debug, Clone, Default)]
pub struct PackageManagerConfigs {
    /// npm/JS package manager configuration.
    pub npm: NpmConfig,
    /// Go module ecosystem configuration.
    pub go: GoConfig,
    /// Rust/Cargo ecosystem configuration.
    pub cargo: CargoConfig,
    /// Python/pip ecosystem configuration.
    pub pip: PipConfig,
    /// Homebrew ecosystem configuration.
    pub homebrew: HomebrewConfig,
    /// Docker image safety configuration.
    pub docker: DockerConfig,
    /// NuGet/.NET ecosystem configuration.
    pub nuget: NugetConfig,
    /// Maven ecosystem configuration.
    pub maven: MavenConfig,
    /// Gradle ecosystem configuration.
    pub gradle: GradleConfig,
}

/// Result of checking whether a package exists on a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageCheckResult {
    /// Package exists on the registry.
    Exists,
    /// Package does NOT exist on the registry.
    NotFound,
    /// The check could not be completed.
    CheckFailed(String),
}

/// Known package registry type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Registry {
    Npm,
    PyPI,
    Go,
    CratesIo,
    Homebrew,
    NuGet,
    MavenCentral,
    GradlePlugin,
}

impl std::fmt::Display for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPI => write!(f, "PyPI"),
            Self::Go => write!(f, "Go"),
            Self::CratesIo => write!(f, "crates.io"),
            Self::Homebrew => write!(f, "Homebrew"),
            Self::NuGet => write!(f, "NuGet"),
            Self::MavenCentral => write!(f, "Maven Central"),
            Self::GradlePlugin => write!(f, "Gradle Plugin Portal"),
        }
    }
}

/// Testable package existence checker seam.
pub trait PackageChecker {
    fn check(&self, name: &str, registry: &Registry) -> PackageCheckResult;
}

/// Cross-platform HTTP package checker.
#[derive(Debug, Clone, Copy)]
pub struct HttpPackageChecker {
    timeout_secs: u64,
}

impl HttpPackageChecker {
    #[must_use]
    pub const fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

impl PackageChecker for HttpPackageChecker {
    fn check(&self, name: &str, registry: &Registry) -> PackageCheckResult {
        check_package_exists_with_timeout(name, registry, self.timeout_secs)
    }
}

/// Outcome from evaluating package policy.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PackagePolicyOutcome {
    pub warnings: Vec<String>,
    pub block: Option<String>,
}

impl PackagePolicyOutcome {
    fn allow() -> Self {
        Self::default()
    }

    const fn block(message: String) -> Self {
        Self {
            warnings: Vec::new(),
            block: Some(message),
        }
    }

    const fn warn(warnings: Vec<String>) -> Self {
        Self {
            warnings,
            block: None,
        }
    }
}

/// Split a compound shell string into individual command fragments.
pub(crate) fn split_shell_commands(input: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut start = 0;
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let b = bytes[i];

        if b == b'\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single_quote && i + 1 < len {
            i += 2;
            continue;
        }

        if !in_single_quote && !in_double_quote {
            if i + 1 < len
                && ((b == b'&' && bytes[i + 1] == b'&') || (b == b'|' && bytes[i + 1] == b'|'))
            {
                let fragment = &input[start..i];
                if !fragment.trim().is_empty() {
                    commands.push(fragment.trim());
                }
                i += 2;
                start = i;
                continue;
            }
            if b == b';' || b == b'\n' || b == b'`' {
                let fragment = &input[start..i];
                if !fragment.trim().is_empty() {
                    commands.push(fragment.trim());
                }
                i += 1;
                start = i;
                continue;
            }
            if b == b'|' {
                let fragment = &input[start..i];
                if !fragment.trim().is_empty() {
                    commands.push(fragment.trim());
                }
                i += 1;
                start = i;
                continue;
            }
            if b == b'$' && i + 1 < len && bytes[i + 1] == b'(' {
                let fragment = &input[start..i];
                if !fragment.trim().is_empty() {
                    commands.push(fragment.trim());
                }
                i += 2;
                start = i;
                continue;
            }
        }
        i += 1;
    }

    if in_single_quote || in_double_quote {
        return split_shell_commands_unquoted(input);
    }

    let fragment = &input[start..];
    if !fragment.trim().is_empty() {
        commands.push(fragment.trim());
    }
    commands
}

fn split_shell_commands_unquoted(input: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut start = 0;
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let b = bytes[i];

        if i + 1 < len
            && ((b == b'&' && bytes[i + 1] == b'&') || (b == b'|' && bytes[i + 1] == b'|'))
        {
            let fragment = &input[start..i];
            if !fragment.trim().is_empty() {
                commands.push(fragment.trim());
            }
            i += 2;
            start = i;
            continue;
        }
        if b == b';' || b == b'\n' || b == b'`' {
            let fragment = &input[start..i];
            if !fragment.trim().is_empty() {
                commands.push(fragment.trim());
            }
            i += 1;
            start = i;
            continue;
        }
        if b == b'|' {
            let fragment = &input[start..i];
            if !fragment.trim().is_empty() {
                commands.push(fragment.trim());
            }
            i += 1;
            start = i;
            continue;
        }
        if b == b'$' && i + 1 < len && bytes[i + 1] == b'(' {
            let fragment = &input[start..i];
            if !fragment.trim().is_empty() {
                commands.push(fragment.trim());
            }
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }

    let fragment = &input[start..];
    if !fragment.trim().is_empty() {
        commands.push(fragment.trim());
    }
    commands
}

/// Extract all package names from a possibly compound command string.
pub(crate) fn extract_all_packages(command: &str) -> Vec<(String, Registry)> {
    let mut all_packages = Vec::new();

    for fragment in split_shell_commands(command) {
        all_packages.extend(extract_packages_from_fragment(fragment));
    }

    all_packages
}

fn extract_packages_from_fragment(fragment: &str) -> Vec<(String, Registry)> {
    let normalised = fragment.replace('\t', " ");
    let trimmed = normalised.trim();

    let npm_prefixes: &[&str] = &[
        "npm install ",
        "npm i ",
        "npm ci ",
        "pnpm install ",
        "pnpm add ",
        "pnpm i ",
        "yarn add ",
        "bun install ",
        "bun add ",
        "bun i ",
    ];
    for prefix in npm_prefixes {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if *prefix == "npm ci " {
                return Vec::new();
            }
            return parse_package_args(rest, &Registry::Npm);
        }
    }

    if trimmed == "npm ci" {
        return Vec::new();
    }

    if let Some(rest) = trimmed.strip_prefix("npx ") {
        return extract_npx_package(rest);
    }

    let pip_prefixes: &[&str] = &["pip install ", "pip3 install ", "uv pip install "];
    for prefix in pip_prefixes {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return parse_package_args(rest, &Registry::PyPI);
        }
    }

    let go_prefixes: &[&str] = &["go get ", "go install "];
    for prefix in go_prefixes {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return parse_go_module_args(rest);
        }
    }

    let cargo_prefixes: &[&str] = &["cargo add ", "cargo install "];
    for prefix in cargo_prefixes {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return parse_cargo_args(rest);
        }
    }

    let homebrew_prefixes: &[&str] = &["brew install ", "brew reinstall ", "brew upgrade "];
    for prefix in homebrew_prefixes {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return parse_homebrew_args(rest);
        }
    }

    if let Some(pkg) = parse_dotnet_add_package(trimmed) {
        return vec![(pkg, Registry::NuGet)];
    }
    if let Some(pkg) = parse_dotnet_tool_install(trimmed) {
        return vec![(pkg, Registry::NuGet)];
    }
    if let Some(pkg) = parse_dotnet_new_install(trimmed) {
        return vec![(pkg, Registry::NuGet)];
    }
    if let Some(pkg) = parse_dotnet_workload_install(trimmed) {
        return vec![(pkg, Registry::NuGet)];
    }
    if let Some(pkg) = parse_nuget_install(trimmed) {
        return vec![(pkg, Registry::NuGet)];
    }
    if let Some(coord) = parse_maven_dependency_get(trimmed) {
        return vec![(coord, Registry::MavenCentral)];
    }

    Vec::new()
}

fn extract_npx_package(args: &str) -> Vec<(String, Registry)> {
    let mut tokens = args.split_whitespace().peekable();
    let mut skip_next = false;

    while let Some(token) = tokens.next() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token == "--" {
            break;
        }
        if let Some(pkg) = token.strip_prefix("--package=") {
            let name = extract_pkg_name_from_token(pkg);
            if !name.is_empty() {
                return vec![(name.to_owned(), Registry::Npm)];
            }
            continue;
        }
        if token == "--package" || token == "-p" {
            if let Some(&next) = tokens.peek() {
                let name = extract_pkg_name_from_token(next);
                if !name.is_empty() {
                    return vec![(name.to_owned(), Registry::Npm)];
                }
            }
            skip_next = true;
            continue;
        }
        if token.starts_with('-') {
            continue;
        }

        let name = extract_pkg_name_from_token(token);
        if !name.is_empty() {
            return vec![(name.to_owned(), Registry::Npm)];
        }
    }

    Vec::new()
}

fn parse_package_args(args: &str, registry: &Registry) -> Vec<(String, Registry)> {
    let mut packages = Vec::new();
    let mut skip_next = false;

    for token in args.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.starts_with('-') {
            let value_flags: &[&str] = &[
                "--registry",
                "--cache",
                "--prefix",
                "--tag",
                "--target",
                "--index-url",
                "--extra-index-url",
                "--constraint",
                "--requirement",
                "--find-links",
                "-e",
                "--editable",
                "--only-binary",
                "--no-binary",
            ];
            if value_flags.contains(&token) {
                skip_next = true;
            }
            continue;
        }
        let name = extract_pkg_name_from_token(token);
        if !name.is_empty() {
            packages.push((name.to_owned(), registry.clone()));
        }
    }
    packages
}

fn extract_pkg_name_from_token(token: &str) -> &str {
    token.strip_prefix('@').map_or_else(
        || token.find('@').map_or(token, |at_pos| &token[..at_pos]),
        |after_at| {
            after_at
                .find('@')
                .map_or(token, |second_at| &token[..=second_at])
        },
    )
}

/// Validate package names used in simple registry URL interpolation.
pub(crate) fn is_valid_curl_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    if name.starts_with('.') || name.starts_with('-') {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    name.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'@' || b == b'/' || b == b'_' || b == b'.' || b == b'-'
    })
}

fn parse_go_module_args(args: &str) -> Vec<(String, Registry)> {
    let mut modules = Vec::new();

    for token in args.split_whitespace() {
        if token.starts_with('-') {
            continue;
        }
        if token.starts_with("./") || token.starts_with("../") || token == "." || token == ".." {
            continue;
        }
        if token == "all" {
            continue;
        }

        let module_path = token.find('@').map_or(token, |at| &token[..at]);
        let module_path = module_path.strip_suffix("/...").unwrap_or(module_path);

        if is_valid_go_module_path(module_path) {
            modules.push((module_path.to_owned(), Registry::Go));
        }
    }

    modules
}

pub(crate) fn parse_cargo_args(args: &str) -> Vec<(String, Registry)> {
    const VALUE_FLAGS: &[&str] = &[
        "--features",
        "-F",
        "--registry",
        "--version",
        "--branch",
        "--tag",
        "--rev",
        "--path",
        "--git",
        "--target-dir",
        "--root",
        "--index",
        "--rename",
    ];

    let mut crates = Vec::new();
    let mut skip_next = false;

    for token in args.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }

        if token.starts_with('-') {
            if token.contains('=') {
                continue;
            }
            if VALUE_FLAGS.contains(&token) {
                skip_next = true;
            }
            continue;
        }

        if token.contains('/') || token.starts_with('.') {
            continue;
        }

        let name = token.find('@').map_or(token, |at| &token[..at]);

        if is_valid_crate_name(name) {
            crates.push((name.to_owned(), Registry::CratesIo));
        }
    }

    crates
}

fn parse_homebrew_args(args: &str) -> Vec<(String, Registry)> {
    const VALUE_FLAGS: &[&str] = &[
        "--appdir",
        "--audio-unit-plugindir",
        "--branch",
        "--cc",
        "--colorpickerdir",
        "--dictionarydir",
        "--env",
        "--fontdir",
        "--input-methoddir",
        "--internet-plugindir",
        "--language",
        "--mdimporterdir",
        "--prefpanedir",
        "--qlplugindir",
        "--screen-saverdir",
        "--vst-plugindir",
        "--vst3-plugindir",
    ];

    let mut packages = Vec::new();
    let mut skip_next = false;

    for token in args.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token == "--" {
            continue;
        }
        if token.starts_with('-') {
            if token.contains('=') {
                continue;
            }
            if VALUE_FLAGS.contains(&token) {
                skip_next = true;
            }
            continue;
        }
        if is_homebrew_external_formula_ref(token) || homebrew_tap_from_package(token).is_some() {
            continue;
        }
        if is_valid_homebrew_token(token) {
            packages.push((token.to_owned(), Registry::Homebrew));
        }
    }

    packages
}

fn token_after_command<'a>(trimmed: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = trimmed.strip_prefix(prefix)?;
    first_non_flag_token(rest)
}

fn first_non_flag_token(args: &str) -> Option<&str> {
    let mut skip_next = false;
    for token in args.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.starts_with('-') {
            if token.contains('=') {
                continue;
            }
            if matches!(
                token,
                "--version"
                    | "-v"
                    | "--source"
                    | "-s"
                    | "--configfile"
                    | "--framework"
                    | "-f"
                    | "--output"
                    | "-o"
                    | "--verbosity"
            ) {
                skip_next = true;
            }
            continue;
        }
        return Some(token);
    }
    None
}

fn parse_dotnet_add_package(trimmed: &str) -> Option<String> {
    if !trimmed.starts_with("dotnet add ") {
        return None;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let pkg_pos = tokens.iter().position(|t| *t == "package")?;
    let name = tokens.get(pkg_pos + 1)?;
    is_valid_nuget_package_name(name).then(|| (*name).to_owned())
}

fn parse_dotnet_tool_install(trimmed: &str) -> Option<String> {
    token_after_command(trimmed, "dotnet tool install ")
        .filter(|name| is_valid_nuget_package_name(name))
        .map(str::to_owned)
}

fn parse_dotnet_new_install(trimmed: &str) -> Option<String> {
    token_after_command(trimmed, "dotnet new install ")
        .map(strip_dotnet_template_version_suffix)
        .filter(|name| is_valid_nuget_package_name(name))
        .map(str::to_owned)
}

fn parse_dotnet_workload_install(trimmed: &str) -> Option<String> {
    token_after_command(trimmed, "dotnet workload install ")
        .filter(|name| is_valid_nuget_package_name(name))
        .map(str::to_owned)
}

fn parse_nuget_install(trimmed: &str) -> Option<String> {
    token_after_command(trimmed, "nuget install ")
        .filter(|name| is_valid_nuget_package_name(name))
        .map(str::to_owned)
}

fn strip_dotnet_template_version_suffix(token: &str) -> &str {
    token.split_once("::").map_or(token, |(name, _)| name)
}

fn parse_maven_dependency_get(trimmed: &str) -> Option<String> {
    if !trimmed.starts_with("mvn ")
        && !trimmed.starts_with("./mvnw ")
        && !trimmed.starts_with("mvnw ")
    {
        return None;
    }
    if !trimmed.contains("dependency:get") {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
    while let Some(token) = tokens.next() {
        let artifact = token
            .strip_prefix("-Dartifact=")
            .or_else(|| token.strip_prefix("-Dartifact:"));
        if let Some(value) = artifact {
            return maven_artifact_to_coordinate(value);
        }
        if token == "-Dartifact" {
            if let Some(next) = tokens.next() {
                return maven_artifact_to_coordinate(next);
            }
        }
    }
    None
}

fn maven_artifact_to_coordinate(value: &str) -> Option<String> {
    let mut parts = value.split(':');
    let group = parts.next()?;
    let artifact = parts.next()?;
    if group.is_empty() || artifact.is_empty() {
        return None;
    }
    let coord = format!("{group}:{artifact}");
    is_valid_maven_coordinate(&coord).then_some(coord)
}

/// Validate a Go module path.
pub(crate) fn is_valid_go_module_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return false;
    }

    let Some(first_slash) = path.find('/') else {
        return false;
    };

    let domain = &path[..first_slash];
    if !domain.contains('.') {
        return false;
    }

    path.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'.' || b == b'-')
}

/// Encode a Go module path for the module proxy URL.
pub(crate) fn go_module_case_encode(module: &str) -> String {
    let mut encoded = String::with_capacity(module.len() + 8);
    for ch in module.chars() {
        if ch.is_ascii_uppercase() {
            encoded.push('!');
            encoded.push(ch.to_ascii_lowercase());
        } else {
            encoded.push(ch);
        }
    }
    encoded
}

/// Compute the sparse index URL path for a crate name.
pub(crate) fn crate_sparse_index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        0 => String::new(),
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

/// Validate a Cargo crate name.
pub(crate) fn is_valid_crate_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let first = name.as_bytes()[0];
    if !first.is_ascii_alphabetic() {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validate a Homebrew formula/cask token.
pub(crate) fn is_valid_homebrew_token(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    if name.starts_with('.') || name.starts_with('-') || name.contains("..") {
        return false;
    }
    name.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'@' || b == b'+'
    })
}

fn is_homebrew_external_formula_ref(token: &str) -> bool {
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("file://")
        || std::path::Path::new(token)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rb"))
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with('/')
}

fn homebrew_tap_from_package(token: &str) -> Option<String> {
    let mut parts = token.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let formula = parts.next()?;
    if parts.next().is_some() || owner.is_empty() || repo.is_empty() || formula.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Validate `NuGet` package IDs.
pub(crate) fn is_valid_nuget_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 || name.contains("..") {
        return false;
    }
    let first = name.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Validate Maven `groupId:artifactId` coordinates.
pub(crate) fn is_valid_maven_coordinate(name: &str) -> bool {
    let Some((group, artifact)) = name.split_once(':') else {
        return false;
    };
    is_valid_maven_part(group, true) && is_valid_maven_part(artifact, false)
}

fn is_valid_maven_part(part: &str, require_dot: bool) -> bool {
    if part.is_empty() || part.len() > 214 || part.starts_with('.') || part.contains("..") {
        return false;
    }
    if require_dot && !part.contains('.') {
        return false;
    }
    part.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

fn is_valid_gradle_plugin_id(name: &str) -> bool {
    is_valid_maven_part(name, true)
}

/// Check whether a package exists using the default HTTP checker.
#[cfg(test)]
pub(crate) fn check_package_exists(name: &str, registry: &Registry) -> PackageCheckResult {
    check_package_exists_with_timeout(name, registry, 5)
}

fn check_package_exists_with_timeout(
    name: &str,
    registry: &Registry,
    timeout_secs: u64,
) -> PackageCheckResult {
    if let Some(error) = validate_registry_name(name, registry) {
        return PackageCheckResult::CheckFailed(error);
    }

    #[cfg(test)]
    {
        let _ = timeout_secs;
        PackageCheckResult::CheckFailed(
            "live registry checks are disabled in unit tests".to_owned(),
        )
    }

    #[cfg(not(test))]
    {
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("sanctum-package-policy/0.5")
            .build()
        {
            Ok(client) => client,
            Err(e) => return PackageCheckResult::CheckFailed(format!("HTTP client error: {e}")),
        };

        for url in registry_urls(name, registry) {
            match check_url(&client, &url) {
                PackageCheckResult::NotFound => {}
                other => return other,
            }
        }
        PackageCheckResult::NotFound
    }
}

#[cfg(not(test))]
fn check_url(client: &reqwest::blocking::Client, url: &str) -> PackageCheckResult {
    let response = client.head(url).send().or_else(|e| {
        if e.is_status() {
            return Err(e);
        }
        client.get(url).send()
    });
    match response {
        Ok(resp) => match resp.status().as_u16() {
            200 => PackageCheckResult::Exists,
            404 | 410 | 451 => PackageCheckResult::NotFound,
            405 => match client.get(url).send() {
                Ok(get_resp) => match get_resp.status().as_u16() {
                    200 => PackageCheckResult::Exists,
                    404 | 410 | 451 => PackageCheckResult::NotFound,
                    code => {
                        PackageCheckResult::CheckFailed(format!("registry returned HTTP {code}"))
                    }
                },
                Err(e) => PackageCheckResult::CheckFailed(format!("registry check failed: {e}")),
            },
            code => PackageCheckResult::CheckFailed(format!("registry returned HTTP {code}")),
        },
        Err(e) => PackageCheckResult::CheckFailed(format!("registry check failed: {e}")),
    }
}

fn validate_registry_name(name: &str, registry: &Registry) -> Option<String> {
    match registry {
        Registry::CratesIo => {
            (!is_valid_crate_name(name)).then(|| format!("invalid crate name: {name}"))
        }
        Registry::Homebrew => (!is_valid_homebrew_token(name))
            .then(|| format!("invalid Homebrew formula/cask name: {name}")),
        Registry::NuGet => (!is_valid_nuget_package_name(name))
            .then(|| format!("invalid NuGet package ID: {name}")),
        Registry::MavenCentral => {
            (!is_valid_maven_coordinate(name)).then(|| format!("invalid Maven coordinate: {name}"))
        }
        Registry::GradlePlugin => {
            (!is_valid_gradle_plugin_id(name)).then(|| format!("invalid Gradle plugin ID: {name}"))
        }
        _ => (!is_valid_curl_package_name(name)).then(|| format!("invalid package name: {name}")),
    }
}

fn registry_urls(name: &str, registry: &Registry) -> Vec<String> {
    match registry {
        Registry::Npm => vec![format!("https://registry.npmjs.org/{name}")],
        Registry::PyPI => vec![format!("https://pypi.org/pypi/{name}/json")],
        Registry::Go => {
            let encoded = go_module_case_encode(name);
            vec![format!("https://proxy.golang.org/{encoded}/@latest")]
        }
        Registry::CratesIo => {
            let path = crate_sparse_index_path(name);
            vec![format!("https://index.crates.io/{path}")]
        }
        Registry::Homebrew => vec![
            format!("https://formulae.brew.sh/api/formula/{name}.json"),
            format!("https://formulae.brew.sh/api/cask/{name}.json"),
        ],
        Registry::NuGet => vec![format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            name.to_ascii_lowercase()
        )],
        Registry::MavenCentral => {
            let (group, artifact) = name.split_once(':').unwrap_or(("", ""));
            vec![format!(
                "https://repo1.maven.org/maven2/{}/{}/maven-metadata.xml",
                group.replace('.', "/"),
                artifact
            )]
        }
        Registry::GradlePlugin => vec![format!("https://plugins.gradle.org/plugin/{name}")],
    }
}

/// Package manager install command patterns for npm/pnpm/yarn/bun.
const NPM_INSTALL_PATTERNS: &[&str] = &[
    "npm install ",
    "npm i ",
    "npm ci ",
    "npx ",
    "pnpm install ",
    "pnpm add ",
    "pnpm i ",
    "yarn add ",
    "bun install ",
    "bun add ",
    "bun i ",
];

pub(crate) fn is_npm_install_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        NPM_INSTALL_PATTERNS
            .iter()
            .any(|pat| trimmed.starts_with(pat) || trimmed == pat.trim_end())
    })
}

pub(crate) fn is_pip_install_command(command: &str) -> bool {
    let pip_patterns: &[&str] = &["pip install ", "pip3 install ", "uv pip install "];
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        pip_patterns
            .iter()
            .any(|pat| trimmed.starts_with(pat) || trimmed == pat.trim_end())
    })
}

const GO_INSTALL_PATTERNS: &[&str] = &["go get ", "go install "];

pub(crate) fn is_go_install_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        GO_INSTALL_PATTERNS
            .iter()
            .any(|pat| trimmed.starts_with(pat) || trimmed == pat.trim_end())
    })
}

const CARGO_ADD_INSTALL_PATTERNS: &[&str] = &["cargo add ", "cargo install "];

pub(crate) fn is_cargo_add_or_install_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        CARGO_ADD_INSTALL_PATTERNS
            .iter()
            .any(|pat| trimmed.starts_with(pat) || trimmed == pat.trim_end())
    })
}

const HOMEBREW_COMMAND_PATTERNS: &[&str] = &[
    "brew install ",
    "brew reinstall ",
    "brew upgrade ",
    "brew tap ",
    "brew bundle ",
];

pub(crate) fn is_homebrew_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        HOMEBREW_COMMAND_PATTERNS
            .iter()
            .any(|pat| trimmed.starts_with(pat) || trimmed == pat.trim_end())
    })
}

fn is_nuget_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let trimmed = frag.trim();
        trimmed.starts_with("dotnet add ")
            || trimmed.starts_with("dotnet tool install ")
            || trimmed.starts_with("dotnet new install ")
            || trimmed.starts_with("dotnet workload install ")
            || trimmed.starts_with("nuget install ")
    })
}

fn is_dotnet_implicit_restore_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let trimmed = frag.trim();
        [
            "dotnet restore",
            "dotnet build",
            "dotnet test",
            "dotnet publish",
            "dotnet run",
        ]
        .iter()
        .any(|cmd| trimmed == *cmd || trimmed.starts_with(&format!("{cmd} ")))
            || trimmed.starts_with("msbuild ") && trimmed.contains("/restore")
    })
}

pub(crate) fn is_maven_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let trimmed = frag.trim();
        trimmed.starts_with("mvn ")
            || trimmed.starts_with("./mvnw ")
            || trimmed.starts_with("mvnw ")
    })
}

fn is_gradle_resolve_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let trimmed = frag.trim();
        let is_gradle = trimmed.starts_with("gradle ")
            || trimmed.starts_with("./gradlew ")
            || trimmed.starts_with("gradlew ");
        is_gradle
            && [
                " build",
                " test",
                " check",
                " dependencies",
                " dependencyInsight",
                " publish",
                " run",
                " --refresh-dependencies",
            ]
            .iter()
            .any(|needle| trimmed.contains(needle))
    })
}

fn extract_homebrew_external_formula_refs(command: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for fragment in split_shell_commands(command) {
        let normalised = fragment.replace('\t', " ");
        let trimmed = normalised.trim();
        let rest = trimmed
            .strip_prefix("brew install ")
            .or_else(|| trimmed.strip_prefix("brew reinstall "));
        let Some(rest) = rest else {
            continue;
        };
        for token in rest.split_whitespace() {
            if is_homebrew_external_formula_ref(token) {
                refs.push(token.to_owned());
            }
        }
    }
    refs
}

fn extract_homebrew_taps(command: &str) -> Vec<String> {
    let mut taps = Vec::new();
    for fragment in split_shell_commands(command) {
        let normalised = fragment.replace('\t', " ");
        let trimmed = normalised.trim();
        let Some(rest) = trimmed.strip_prefix("brew tap ") else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.starts_with('-') || token.contains("://") {
                continue;
            }
            if token.matches('/').count() == 1 {
                taps.push(token.to_owned());
                break;
            }
        }
    }
    taps
}

fn extract_homebrew_tap_urls(command: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for fragment in split_shell_commands(command) {
        let normalised = fragment.replace('\t', " ");
        let trimmed = normalised.trim();
        let Some(rest) = trimmed.strip_prefix("brew tap ") else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.contains("://") || token.starts_with("git@") {
                urls.push(token.to_owned());
            }
        }
    }
    urls
}

fn extract_homebrew_package_taps(command: &str) -> Vec<String> {
    let mut taps = Vec::new();
    for fragment in split_shell_commands(command) {
        let normalised = fragment.replace('\t', " ");
        let trimmed = normalised.trim();
        let rest = trimmed
            .strip_prefix("brew install ")
            .or_else(|| trimmed.strip_prefix("brew reinstall "))
            .or_else(|| trimmed.strip_prefix("brew upgrade "));
        let Some(rest) = rest else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.starts_with('-') {
                continue;
            }
            if let Some(tap) = homebrew_tap_from_package(token) {
                taps.push(tap);
            }
        }
    }
    taps
}

fn is_bare_homebrew_upgrade(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        let Some(rest) = trimmed.strip_prefix("brew upgrade") else {
            return false;
        };
        rest.split_whitespace().all(|token| token.starts_with('-'))
    })
}

fn is_homebrew_bundle_command(command: &str) -> bool {
    split_shell_commands(command).iter().any(|frag| {
        let normalised = frag.replace('\t', " ");
        let trimmed = normalised.trim();
        let Some(rest) = trimmed.strip_prefix("brew bundle") else {
            return false;
        };
        let rest = rest.trim();
        if rest.is_empty() {
            return true;
        }
        for token in rest.split_whitespace() {
            if token.starts_with('-') {
                continue;
            }
            return token == "install";
        }
        true
    })
}

fn extract_nuget_sources(command: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for fragment in split_shell_commands(command) {
        let mut tokens = fragment.split_whitespace();
        while let Some(token) = tokens.next() {
            let lower = token.to_ascii_lowercase();
            if matches!(lower.as_str(), "--source" | "-s" | "-source") {
                if let Some(source) = tokens.next() {
                    sources.push(source.to_owned());
                }
                continue;
            }
            for prefix in ["--source=", "-s=", "-source="] {
                if lower.starts_with(prefix) {
                    sources.push(token[prefix.len()..].to_owned());
                }
            }
        }
    }
    sources
}

/// Evaluate package-manager policy for a shell command.
#[allow(clippy::too_many_lines)]
pub fn evaluate_command_policy(
    command: &str,
    configs: &PackageManagerConfigs,
    checker: &dyn PackageChecker,
    check_package_existence: bool,
) -> PackagePolicyOutcome {
    let normalised = command.replace('\t', " ");
    let is_npm_install = is_npm_install_command(command);
    let is_pip_install = is_pip_install_command(command);
    let is_go_install = is_go_install_command(command);
    let is_cargo_add_install = is_cargo_add_or_install_command(command);
    let is_homebrew = is_homebrew_command(command);
    let is_nuget = is_nuget_command(command);
    let is_maven = is_maven_command(command);
    let is_gradle = is_gradle_resolve_command(command);

    if is_npm_install
        && configs.npm.ignore_scripts_required
        && !normalised.contains("--ignore-scripts")
    {
        return PackagePolicyOutcome::block(
            "Blocked: npm install without --ignore-scripts is not permitted by policy\n\
             To proceed: add --ignore-scripts to the command, or disable \
             ignore_scripts_required in your Sanctum config"
                .to_owned(),
        );
    }

    if is_pip_install
        && configs.pip.require_binary_only
        && !normalised.contains("--only-binary :all:")
        && !normalised.contains("--only-binary=:all:")
    {
        return PackagePolicyOutcome::block(
            "Blocked: pip install without --only-binary :all: allows setup.py code execution \
             (source distributions can run arbitrary code during install, similar to npm postinstall scripts)\n\
             To proceed: add --only-binary :all: to the command, or disable \
             require_binary_only in your Sanctum config [sentinel.pip]"
                .to_owned(),
        );
    }

    let mut warnings = Vec::new();
    let packages = extract_all_packages(command);

    if is_npm_install
        || is_pip_install
        || is_go_install
        || is_cargo_add_install
        || is_homebrew
        || is_nuget
        || is_maven
    {
        for (name, registry) in &packages {
            if is_allowlisted(name, registry, configs) {
                continue;
            }
            if !check_package_existence {
                continue;
            }
            match checker.check(name, registry) {
                PackageCheckResult::Exists => {}
                PackageCheckResult::NotFound => {
                    return PackagePolicyOutcome::block(package_not_found_message(name, registry));
                }
                PackageCheckResult::CheckFailed(reason) => {
                    warnings.push(format!(
                        "Could not verify package '{name}' on {registry}: {reason}. \
                         Install will proceed, but package legitimacy is unconfirmed. \
                         If this persists, check your internet connection or adjust \
                         package_check_timeout_ms in your Sanctum config."
                    ));
                }
            }
        }
    }

    if is_homebrew {
        add_homebrew_warnings(command, &normalised, configs, &mut warnings);
        if configs.homebrew.block_external_formula_installs {
            let external_refs = extract_homebrew_external_formula_refs(command);
            if !external_refs.is_empty() {
                return PackagePolicyOutcome::block(format!(
                    "Blocked: Homebrew install from direct formula URL/path ({}) is not permitted by policy\n\
                     Formula files are Ruby code executed during install. Use a trusted tap, or run directly in your terminal after review.",
                    external_refs.join(", ")
                ));
            }
        }
    }

    if is_nuget {
        add_nuget_source_warnings(command, configs, &mut warnings);
    }

    if configs.nuget.warn_implicit_restore && is_dotnet_implicit_restore_command(command) {
        warnings.push(
            "Warning: dotnet/msbuild command may restore NuGet packages implicitly. \
             Prefer an explicit audited restore step on sensitive machines."
                .to_owned(),
        );
    }

    if is_gradle {
        warnings.push(
            "Warning: Gradle command may resolve dependencies/plugins without per-package verification. \
             Review build.gradle(.kts), plugin repositories, and lockfiles before running."
                .to_owned(),
        );
    }

    if is_npm_install
        && configs.npm.ignore_scripts_warning
        && !packages.is_empty()
        && !normalised.contains("--ignore-scripts")
    {
        warnings.push(
            "Tip: consider using --ignore-scripts to prevent lifecycle script execution".to_owned(),
        );
    }

    if is_pip_install
        && configs.pip.warn_source_installs
        && !normalised.contains("--only-binary :all:")
        && !normalised.contains("--only-binary=:all:")
        && !packages.is_empty()
    {
        warnings.push(
            "Tip: consider --only-binary :all: to prevent setup.py execution during install. \
             Source distributions can execute arbitrary code (like npm postinstall scripts)."
                .to_owned(),
        );
    }

    if warnings.is_empty() {
        PackagePolicyOutcome::allow()
    } else {
        PackagePolicyOutcome::warn(warnings)
    }
}

fn is_allowlisted(name: &str, registry: &Registry, configs: &PackageManagerConfigs) -> bool {
    match registry {
        Registry::Npm => configs.npm.allowlist.iter().any(|a| a == name),
        Registry::PyPI => configs.pip.allowlist.iter().any(|a| a == name),
        Registry::Go => {
            configs.go.allowlist.iter().any(|a| a == name)
                || configs
                    .go
                    .trusted_prefixes
                    .iter()
                    .any(|prefix| name.starts_with(prefix.as_str()))
        }
        Registry::CratesIo => configs.cargo.allowlist.iter().any(|a| a == name),
        Registry::Homebrew => configs.homebrew.allowlist.iter().any(|a| a == name),
        Registry::NuGet => configs.nuget.allowlist.iter().any(|a| a == name),
        Registry::MavenCentral => {
            configs.maven.allowlist.iter().any(|a| a == name)
                || configs
                    .maven
                    .trusted_prefixes
                    .iter()
                    .any(|prefix| name.starts_with(prefix.as_str()))
        }
        Registry::GradlePlugin => {
            configs.gradle.allowlist.iter().any(|a| a == name)
                || configs
                    .gradle
                    .trusted_prefixes
                    .iter()
                    .any(|prefix| name.starts_with(prefix.as_str()))
        }
    }
}

fn package_not_found_message(name: &str, registry: &Registry) -> String {
    match registry {
        Registry::Go => format!(
            "Blocked: module '{name}' not found on Go \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://pkg.go.dev/{name}, add to \
             [sentinel.go] allowlist, or run directly in your terminal"
        ),
        Registry::CratesIo => format!(
            "Blocked: crate '{name}' not found on crates.io \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://crates.io/crates/{name}, add to \
             [sentinel.cargo] allowlist, or run directly in your terminal"
        ),
        Registry::Npm => format!(
            "Blocked: package '{name}' not found on npm \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://www.npmjs.com/package/{name}, add to \
             [sentinel.npm] allowlist, or run directly in your terminal"
        ),
        Registry::PyPI => format!(
            "Blocked: package '{name}' not found on PyPI \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://pypi.org/project/{name}, add to \
             [sentinel.pip] allowlist, or run directly in your terminal"
        ),
        Registry::Homebrew => format!(
            "Blocked: formula/cask '{name}' not found in Homebrew core/cask \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://formulae.brew.sh/search?term={name}, add to \
             [sentinel.homebrew] allowlist, or run directly in your terminal"
        ),
        Registry::NuGet => format!(
            "Blocked: package '{name}' not found on NuGet \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://www.nuget.org/packages/{name}, add to \
             [sentinel.nuget] allowlist, or run directly in your terminal"
        ),
        Registry::MavenCentral => format!(
            "Blocked: artifact '{name}' not found on Maven Central \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://central.sonatype.com/artifact/{name}, add to \
             [sentinel.maven] allowlist, or run directly in your terminal"
        ),
        Registry::GradlePlugin => format!(
            "Blocked: plugin '{name}' not found on the Gradle Plugin Portal \
             (possible typosquatting/slopsquatting)\n\
             To proceed: verify at https://plugins.gradle.org/plugin/{name}, add to \
             [sentinel.gradle] allowlist, or run directly in your terminal"
        ),
    }
}

fn add_homebrew_warnings(
    command: &str,
    normalised: &str,
    configs: &PackageManagerConfigs,
    warnings: &mut Vec<String>,
) {
    let homebrew_config = &configs.homebrew;

    if homebrew_config.warn_untrusted_taps {
        let mut taps = extract_homebrew_taps(command);
        taps.extend(extract_homebrew_package_taps(command));
        taps.sort();
        taps.dedup();
        for tap in taps {
            if !homebrew_config
                .trusted_taps
                .iter()
                .any(|trusted| trusted == &tap)
            {
                warnings.push(format!(
                    "Warning: Homebrew tap '{tap}' is not in [sentinel.homebrew] trusted_taps. \
                     Formulae/casks from taps can execute install and post-install code."
                ));
            }
        }

        for tap_url in extract_homebrew_tap_urls(command) {
            warnings.push(format!(
                "Warning: brew tap uses explicit remote URL '{tap_url}'. \
                 Verify the repository before trusting formulae or casks from this tap."
            ));
        }
    }

    if homebrew_config.warn_no_quarantine && normalised.contains("--no-quarantine") {
        warnings.push(
            "Warning: brew --no-quarantine disables macOS quarantine checks for casks. \
             Avoid it unless you have independently verified the app."
                .to_owned(),
        );
    }

    if is_bare_homebrew_upgrade(command) {
        warnings.push(
            "Warning: brew upgrade may execute formula/cask install or post-install steps \
             for every outdated package. Review `brew outdated` first on sensitive machines."
                .to_owned(),
        );
    }

    if homebrew_config.warn_brewfile && is_homebrew_bundle_command(command) {
        warnings.push(
            "Warning: brew bundle installs from a Brewfile, including taps and casks. \
             Review the Brewfile before running it in a trusted environment."
                .to_owned(),
        );
    }
}

fn add_nuget_source_warnings(
    command: &str,
    configs: &PackageManagerConfigs,
    warnings: &mut Vec<String>,
) {
    for source in extract_nuget_sources(command) {
        let trusted = configs
            .nuget
            .trusted_sources
            .iter()
            .any(|s| nuget_source_matches_trusted(&source, s));
        if source.to_ascii_lowercase().starts_with("http://") {
            warnings.push(format!(
                "Warning: NuGet source '{source}' uses plain HTTP. Use HTTPS or a trusted local source."
            ));
        } else if !trusted {
            warnings.push(format!(
                "Warning: NuGet source '{source}' is not in [sentinel.nuget] trusted_sources."
            ));
        }
    }
}

fn nuget_source_matches_trusted(source: &str, trusted: &str) -> bool {
    normalise_nuget_source(source) == normalise_nuget_source(trusted)
}

fn normalise_nuget_source(source: &str) -> String {
    let trimmed = source.trim().trim_end_matches('/');
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if path.is_empty() {
            format!(
                "{}://{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase()
            )
        } else {
            format!(
                "{}://{}/{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                path
            )
        }
    } else {
        trimmed.to_owned()
    }
}

/// Evaluate ecosystem config files before an LLM writes them.
pub fn evaluate_project_file_policy(
    file_path: &str,
    content: &str,
    configs: &PackageManagerConfigs,
    checker: &dyn PackageChecker,
    check_package_existence: bool,
) -> PackagePolicyOutcome {
    let lower = file_path.to_ascii_lowercase();
    if lower.ends_with("pom.xml") {
        return evaluate_pom_xml(content, configs, checker, check_package_existence);
    }
    if lower.ends_with("build.gradle") || lower.ends_with("build.gradle.kts") {
        return evaluate_gradle_file(content, configs, checker, check_package_existence);
    }
    PackagePolicyOutcome::allow()
}

fn evaluate_pom_xml(
    content: &str,
    configs: &PackageManagerConfigs,
    checker: &dyn PackageChecker,
    check_package_existence: bool,
) -> PackagePolicyOutcome {
    let parsed = parse_pom_xml(content);
    let mut warnings = Vec::new();

    for repo in parsed.repositories {
        if repo.starts_with("http://") {
            warnings.push(format!(
                "Warning: pom.xml repository '{repo}' uses plain HTTP. Maven dependencies can execute build-time code."
            ));
        } else if !repo.starts_with("https://repo.maven.apache.org/maven2")
            && !repo.starts_with("https://repo1.maven.org/maven2")
        {
            warnings.push(format!(
                "Warning: pom.xml declares non-default Maven repository '{repo}'. Verify it before resolving dependencies."
            ));
        }
    }

    let dependency_outcome = evaluate_declared_packages(
        parsed
            .dependencies
            .into_iter()
            .map(|coord| (coord, Registry::MavenCentral)),
        configs,
        checker,
        check_package_existence,
    );
    if dependency_outcome.block.is_some() {
        return dependency_outcome;
    }
    warnings.extend(dependency_outcome.warnings);

    PackagePolicyOutcome::warn(warnings)
}

fn evaluate_gradle_file(
    content: &str,
    configs: &PackageManagerConfigs,
    checker: &dyn PackageChecker,
    check_package_existence: bool,
) -> PackagePolicyOutcome {
    let parsed = parse_gradle_content(content);
    let mut warnings = Vec::new();

    for repo in parsed.repositories {
        if repo.starts_with("http://") {
            warnings.push(format!(
                "Warning: Gradle repository '{repo}' uses plain HTTP. Use HTTPS or a trusted local mirror."
            ));
        } else if !repo.starts_with("https://repo.maven.apache.org/maven2")
            && !repo.starts_with("https://repo1.maven.org/maven2")
            && !repo.starts_with("https://plugins.gradle.org")
        {
            warnings.push(format!(
                "Warning: Gradle declares non-default repository '{repo}'. Verify it before resolving dependencies."
            ));
        }
    }

    if configs.gradle.warn_dynamic_versions {
        for (name, version) in &parsed.dynamic_versions {
            warnings.push(format!(
                "Warning: Gradle dependency '{name}' uses dynamic version '{version}'. Pin an exact version for supply-chain safety."
            ));
        }
    }

    let dependency_outcome = evaluate_declared_packages(
        parsed
            .dependencies
            .into_iter()
            .map(|coord| (coord, Registry::MavenCentral))
            .chain(
                parsed
                    .plugins
                    .into_iter()
                    .map(|plugin| (plugin, Registry::GradlePlugin)),
            ),
        configs,
        checker,
        check_package_existence,
    );
    if dependency_outcome.block.is_some() {
        return dependency_outcome;
    }
    warnings.extend(dependency_outcome.warnings);

    PackagePolicyOutcome::warn(warnings)
}

fn evaluate_declared_packages<I>(
    packages: I,
    configs: &PackageManagerConfigs,
    checker: &dyn PackageChecker,
    check_package_existence: bool,
) -> PackagePolicyOutcome
where
    I: IntoIterator<Item = (String, Registry)>,
{
    let mut warnings = Vec::new();
    for (name, registry) in packages {
        if is_allowlisted(&name, &registry, configs) || !check_package_existence {
            continue;
        }
        match checker.check(&name, &registry) {
            PackageCheckResult::Exists => {}
            PackageCheckResult::NotFound => {
                return PackagePolicyOutcome::block(package_not_found_message(&name, &registry));
            }
            PackageCheckResult::CheckFailed(reason) => warnings.push(format!(
                "Could not verify package '{name}' on {registry}: {reason}. \
                 Dependency legitimacy is unconfirmed."
            )),
        }
    }
    PackagePolicyOutcome::warn(warnings)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ParsedPom {
    dependencies: Vec<String>,
    repositories: Vec<String>,
}

fn parse_pom_xml(content: &str) -> ParsedPom {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut result = ParsedPom::default();
    let mut tag_stack: Vec<String> = Vec::new();
    let mut in_dependency = false;
    let mut in_repository = false;
    let mut group_id = String::new();
    let mut artifact_id = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "dependency" {
                    in_dependency = true;
                    group_id.clear();
                    artifact_id.clear();
                }
                if tag == "repository" {
                    in_repository = true;
                }
                tag_stack.push(tag);
            }
            Ok(Event::Text(e)) => {
                let text = e
                    .decode()
                    .map_or_else(|_| String::new(), std::borrow::Cow::into_owned);
                if let Some(tag) = tag_stack.last() {
                    if in_dependency && tag == "groupId" {
                        group_id = text;
                    } else if in_dependency && tag == "artifactId" {
                        artifact_id = text;
                    } else if in_repository && tag == "url" {
                        result.repositories.push(text);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "dependency" {
                    in_dependency = false;
                    let coord = format!("{group_id}:{artifact_id}");
                    if is_valid_maven_coordinate(&coord) {
                        result.dependencies.push(coord);
                    }
                }
                if tag == "repository" {
                    in_repository = false;
                }
                let _ = tag_stack.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    result
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ParsedGradle {
    dependencies: Vec<String>,
    plugins: Vec<String>,
    dynamic_versions: Vec<(String, String)>,
    repositories: Vec<String>,
}

fn parse_gradle_content(content: &str) -> ParsedGradle {
    let mut parsed = ParsedGradle::default();
    let Ok(dep_re) = Regex::new(
        r#"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor)\s*(?:\(|\s)\s*["']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+):([^"']+)["']"#,
    ) else {
        return parsed;
    };
    for cap in dep_re.captures_iter(content) {
        let coord = cap.get(1).map_or("", |m| m.as_str()).to_owned();
        let version = cap.get(2).map_or("", |m| m.as_str()).to_owned();
        if is_valid_maven_coordinate(&coord) {
            parsed.dependencies.push(coord.clone());
            if is_dynamic_version(&version) {
                parsed.dynamic_versions.push((coord, version));
            }
        }
    }

    let Ok(plugin_fn_re) =
        Regex::new(r#"\bid\s*\(\s*["']([A-Za-z0-9_.-]+)["']\s*\)\s*version\s*["']([^"']+)["']"#)
    else {
        return parsed;
    };
    for cap in plugin_fn_re.captures_iter(content) {
        add_gradle_plugin_capture(&mut parsed, &cap);
    }

    let Ok(plugin_groovy_re) =
        Regex::new(r#"\bid\s+["']([A-Za-z0-9_.-]+)["']\s+version\s+["']([^"']+)["']"#)
    else {
        return parsed;
    };
    for cap in plugin_groovy_re.captures_iter(content) {
        add_gradle_plugin_capture(&mut parsed, &cap);
    }

    let Ok(repo_re) = Regex::new(r#"url\s*(?:=|\()?\s*["']([^"']+)["']"#) else {
        return parsed;
    };
    for cap in repo_re.captures_iter(content) {
        if let Some(url) = cap.get(1) {
            parsed.repositories.push(url.as_str().to_owned());
        }
    }

    parsed
}

fn add_gradle_plugin_capture(parsed: &mut ParsedGradle, cap: &regex::Captures<'_>) {
    let plugin = cap.get(1).map_or("", |m| m.as_str()).to_owned();
    let version = cap.get(2).map_or("", |m| m.as_str()).to_owned();
    if is_valid_gradle_plugin_id(&plugin) {
        parsed.plugins.push(plugin.clone());
        if is_dynamic_version(&version) {
            parsed.dynamic_versions.push((plugin, version));
        }
    }
}

fn is_dynamic_version(version: &str) -> bool {
    version.contains('+')
        || version.eq_ignore_ascii_case("latest.release")
        || version.eq_ignore_ascii_case("latest.integration")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockPackageChecker {
        responses: HashMap<(String, Registry), PackageCheckResult>,
    }

    impl MockPackageChecker {
        fn with(mut self, name: &str, registry: Registry, result: PackageCheckResult) -> Self {
            self.responses.insert((name.to_owned(), registry), result);
            self
        }
    }

    impl PackageChecker for MockPackageChecker {
        fn check(&self, name: &str, registry: &Registry) -> PackageCheckResult {
            self.responses
                .get(&(name.to_owned(), registry.clone()))
                .cloned()
                .unwrap_or(PackageCheckResult::Exists)
        }
    }

    #[test]
    fn parses_nuget_commands() {
        let pkgs = extract_all_packages("dotnet add package Newtonsoft.Json");
        assert_eq!(pkgs, vec![("Newtonsoft.Json".to_owned(), Registry::NuGet)]);

        let pkgs = extract_all_packages("dotnet add src/App/App.csproj package Serilog");
        assert_eq!(pkgs, vec![("Serilog".to_owned(), Registry::NuGet)]);

        let pkgs = extract_all_packages("dotnet tool install --global dotnetsay");
        assert_eq!(pkgs, vec![("dotnetsay".to_owned(), Registry::NuGet)]);

        let pkgs = extract_all_packages("dotnet new install Contoso.Templates::1.2.3");
        assert_eq!(
            pkgs,
            vec![("Contoso.Templates".to_owned(), Registry::NuGet)]
        );

        let pkgs = extract_all_packages("nuget install NUnit -Version 4.0.0");
        assert_eq!(pkgs, vec![("NUnit".to_owned(), Registry::NuGet)]);

        let pkgs = extract_all_packages("nuget install Foo::1");
        assert!(pkgs.is_empty(), "NuGet package IDs do not use :: versions");
    }

    #[test]
    fn parses_maven_dependency_get() {
        let pkgs = extract_all_packages("mvn dependency:get -Dartifact=com.acme:thing:1.2.3");
        assert_eq!(
            pkgs,
            vec![("com.acme:thing".to_owned(), Registry::MavenCentral)]
        );

        let pkgs = extract_all_packages("./mvnw dependency:get -Dartifact=com.acme:wrapper:1.2.3");
        assert_eq!(
            pkgs,
            vec![("com.acme:wrapper".to_owned(), Registry::MavenCentral)]
        );

        let pkgs = extract_all_packages(
            "echo preparing && mvn dependency:get -Dartifact=com.acme:compound:1.2.3",
        );
        assert_eq!(
            pkgs,
            vec![("com.acme:compound".to_owned(), Registry::MavenCentral)]
        );
    }

    #[test]
    fn validates_nuget_and_maven_names() {
        assert!(is_valid_nuget_package_name("Newtonsoft.Json"));
        assert!(!is_valid_nuget_package_name("../../evil"));
        assert!(is_valid_maven_coordinate("com.google.guava:guava"));
        assert!(!is_valid_maven_coordinate("guava"));
        assert!(!is_valid_maven_coordinate("com.google:../evil"));
    }

    #[test]
    fn mock_checker_blocks_not_found() {
        let checker = MockPackageChecker::default().with(
            "Missing.Package",
            Registry::NuGet,
            PackageCheckResult::NotFound,
        );
        let outcome = evaluate_command_policy(
            "dotnet add package Missing.Package",
            &PackageManagerConfigs::default(),
            &checker,
            true,
        );
        assert!(outcome.block.unwrap().contains("NuGet"));
    }

    #[test]
    fn mock_checker_warns_check_failed() {
        let checker = MockPackageChecker::default().with(
            "com.acme:thing",
            Registry::MavenCentral,
            PackageCheckResult::CheckFailed("timeout".to_owned()),
        );
        let outcome = evaluate_command_policy(
            "mvn dependency:get -Dartifact=com.acme:thing:1.0.0",
            &PackageManagerConfigs::default(),
            &checker,
            true,
        );
        assert!(outcome.block.is_none());
        assert!(outcome.warnings.join("\n").contains("timeout"));
    }

    #[test]
    fn trusted_prefix_skips_maven_check() {
        let checker = MockPackageChecker::default().with(
            "com.google.guava:guava",
            Registry::MavenCentral,
            PackageCheckResult::NotFound,
        );
        let outcome = evaluate_command_policy(
            "mvn dependency:get -Dartifact=com.google.guava:guava:33.0.0",
            &PackageManagerConfigs::default(),
            &checker,
            true,
        );
        assert!(outcome.block.is_none());
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn dotnet_implicit_restore_warns() {
        let outcome = evaluate_command_policy(
            "dotnet build",
            &PackageManagerConfigs::default(),
            &MockPackageChecker::default(),
            true,
        );
        assert!(outcome.warnings.join("\n").contains("implicitly"));
    }

    #[test]
    fn nuget_untrusted_source_warns() {
        let outcome = evaluate_command_policy(
            "dotnet add package Newtonsoft.Json --source https://packages.example.test/v3/index.json",
            &PackageManagerConfigs::default(),
            &MockPackageChecker::default(),
            false,
        );
        assert!(outcome.warnings.join("\n").contains("trusted_sources"));
    }

    #[test]
    fn nuget_source_forms_are_case_insensitive() {
        let mut configs = PackageManagerConfigs::default();
        configs.nuget.trusted_sources = vec!["https://api.nuget.org/v3/index.json".to_owned()];

        let outcome = evaluate_command_policy(
            "dotnet add package Newtonsoft.Json --Source=https://API.NUGET.ORG/v3/index.json/",
            &configs,
            &MockPackageChecker::default(),
            false,
        );
        assert!(
            outcome.warnings.is_empty(),
            "trusted source should not warn: {:?}",
            outcome.warnings
        );

        let outcome = evaluate_command_policy(
            "dotnet add package Newtonsoft.Json --Source=http://packages.example.test/v3/index.json",
            &configs,
            &MockPackageChecker::default(),
            false,
        );
        assert!(outcome.warnings.join("\n").contains("plain HTTP"));
    }

    #[test]
    fn parses_pom_dependencies_and_repositories() {
        let pom = r"
            <project>
              <repositories><repository><url>http://repo.example.test/maven</url></repository></repositories>
              <dependencies>
                <dependency><groupId>com.acme</groupId><artifactId>thing</artifactId><version>1.0</version></dependency>
              </dependencies>
            </project>
        ";
        let parsed = parse_pom_xml(pom);
        assert_eq!(parsed.dependencies, vec!["com.acme:thing"]);
        assert_eq!(parsed.repositories, vec!["http://repo.example.test/maven"]);
    }

    #[test]
    fn pom_not_found_blocks_with_mock() {
        let checker = MockPackageChecker::default().with(
            "com.acme:thing",
            Registry::MavenCentral,
            PackageCheckResult::NotFound,
        );
        let pom = r"
            <project><dependencies>
              <dependency><groupId>com.acme</groupId><artifactId>thing</artifactId></dependency>
            </dependencies></project>
        ";
        let outcome = evaluate_project_file_policy(
            "pom.xml",
            pom,
            &PackageManagerConfigs::default(),
            &checker,
            true,
        );
        assert!(outcome.block.unwrap().contains("Maven Central"));
    }

    #[test]
    fn parses_gradle_dependencies_plugins_and_dynamic_versions() {
        let gradle = r#"
            plugins {
              id("com.github.ben-manes.versions") version "0.+"
            }
            repositories { maven { url "http://repo.example.test/maven" } }
            dependencies {
              implementation("com.acme:thing:1.+")
              testImplementation 'org.example:other:2.0.0'
            }
        "#;
        let parsed = parse_gradle_content(gradle);
        assert!(parsed.dependencies.contains(&"com.acme:thing".to_owned()));
        assert!(parsed
            .plugins
            .contains(&"com.github.ben-manes.versions".to_owned()));
        assert_eq!(parsed.dynamic_versions.len(), 2);
        assert!(parsed
            .repositories
            .contains(&"http://repo.example.test/maven".to_owned()));
    }

    #[test]
    fn gradle_dynamic_version_warns() {
        let gradle = r#"dependencies { implementation("com.acme:thing:1.+") }"#;
        let outcome = evaluate_project_file_policy(
            "build.gradle.kts",
            gradle,
            &PackageManagerConfigs::default(),
            &MockPackageChecker::default(),
            false,
        );
        assert!(outcome.warnings.join("\n").contains("dynamic version"));
    }

    #[test]
    fn invalid_name_injection_rejected_before_http() {
        let result = check_package_exists("../../etc/passwd", &Registry::NuGet);
        assert!(matches!(result, PackageCheckResult::CheckFailed(_)));
    }

    #[test]
    fn registry_urls_are_cross_platform_http_urls() {
        let urls = registry_urls("Newtonsoft.Json", &Registry::NuGet);
        assert_eq!(
            urls[0],
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
        let urls = registry_urls("com.acme:thing", &Registry::MavenCentral);
        assert_eq!(
            urls[0],
            "https://repo1.maven.org/maven2/com/acme/thing/maven-metadata.xml"
        );
        let urls = registry_urls("com.github.ben-manes.versions", &Registry::GradlePlugin);
        assert_eq!(
            urls[0],
            "https://plugins.gradle.org/plugin/com.github.ben-manes.versions"
        );
    }
}
