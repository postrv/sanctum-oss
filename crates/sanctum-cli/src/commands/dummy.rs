//! `sanctum dummy` -- Manage registered dummy secrets for tests and docs.

use std::io::Read;

use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;

use crate::DummyAction;

/// Run the dummy subcommand.
///
/// # Errors
///
/// Returns an error when the registry cannot be loaded or saved, or when
/// command arguments are invalid.
pub fn run(action: &DummyAction) -> Result<(), CliError> {
    let paths = WellKnownPaths::default();
    let path = sanctum_firewall::dummy_registry::registry_path(&paths.data_dir);
    let mut registry = sanctum_firewall::dummy_registry::load_registry(&path)?;

    match action {
        DummyAction::Generate {
            provider,
            label,
            paths,
            require_marker,
        } => {
            let value = generate_dummy_secret(provider)?;
            let entry = registry.mint(&value, provider, label, paths.clone(), *require_marker)?;
            sanctum_firewall::dummy_registry::save_registry(&path, &registry)?;
            print_minted(&value, &entry);
            Ok(())
        }
        DummyAction::Mint {
            provider,
            label,
            paths,
            require_marker,
        } => {
            let value = read_secret_from_stdin()?;
            let entry = registry.mint(&value, provider, label, paths.clone(), *require_marker)?;
            sanctum_firewall::dummy_registry::save_registry(&path, &registry)?;
            print_minted("<redacted stdin value>", &entry);
            Ok(())
        }
        DummyAction::List { json } => {
            if *json {
                let out = serde_json::to_string_pretty(&registry.entries)
                    .map_err(|e| CliError::InvalidArgs(e.to_string()))?;
                #[allow(clippy::print_stdout)]
                {
                    println!("{out}");
                }
            } else {
                #[allow(clippy::print_stdout)]
                {
                    if registry.entries.is_empty() {
                        println!("No dummy secrets registered.");
                    } else {
                        println!("Registered dummy secrets:");
                        for entry in &registry.entries {
                            println!(
                                "  {} [{}] hash={} paths={} marker={}",
                                entry.label,
                                entry.provider,
                                entry.hash_prefix(),
                                entry.allowed_paths.join(","),
                                entry.require_marker
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        DummyAction::Revoke { label, hash } => {
            if label.is_none() && hash.is_none() {
                return Err(CliError::InvalidArgs(
                    "dummy revoke requires --label or --hash".to_owned(),
                ));
            }
            let removed = registry.revoke(label.as_deref(), hash.as_deref());
            sanctum_firewall::dummy_registry::save_registry(&path, &registry)?;
            #[allow(clippy::print_stdout)]
            {
                println!(
                    "Removed {removed} dummy secret entr{}.",
                    if removed == 1 { "y" } else { "ies" }
                );
            }
            Ok(())
        }
    }
}

fn read_secret_from_stdin() -> Result<String, CliError> {
    let mut buf = String::new();
    std::io::stdin()
        .take(16 * 1024)
        .read_to_string(&mut buf)
        .map_err(|e| CliError::InvalidArgs(format!("failed to read secret from stdin: {e}")))?;
    let value = buf.trim().to_owned();
    if value.is_empty() {
        return Err(CliError::InvalidArgs(
            "no dummy secret value provided on stdin".to_owned(),
        ));
    }
    Ok(value)
}

fn generate_dummy_secret(provider: &str) -> Result<String, CliError> {
    let token = sanctum_types::auth::generate_token()?;
    let value = match provider {
        "openai" => format!("sk-proj-dummy{token}"),
        "anthropic" => format!("sk-ant-dummy{token}"),
        "stripe" => format!("sk_test_dummy{token}"),
        "github" => format!("ghp_dummy{token}"),
        other if !other.is_empty() => format!("dummy_{other}_{token}"),
        _ => {
            return Err(CliError::InvalidArgs(
                "provider must not be empty".to_owned(),
            ));
        }
    };
    Ok(value)
}

fn print_minted(value: &str, entry: &sanctum_firewall::dummy_registry::DummySecretEntry) {
    #[allow(clippy::print_stdout)]
    {
        println!("Dummy secret registered: {}", entry.label);
        println!("Provider: {}", entry.provider);
        println!("Hash prefix: {}", entry.hash_prefix());
        println!("Allowed paths: {}", entry.allowed_paths.join(", "));
        if value != "<redacted stdin value>" {
            println!("Value: {value}");
        }
        if entry.require_marker {
            println!(
                "Use marker {} in the test/doc fixture.",
                sanctum_firewall::dummy_registry::DUMMY_SECRET_MARKER
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_openai_dummy_is_shape_valid() {
        let value = generate_dummy_secret("openai").expect("generate");
        assert!(value.starts_with("sk-proj-dummy"));
        assert!(value.len() > 40);
    }

    #[test]
    fn generate_unknown_provider_still_namespaced() {
        let value = generate_dummy_secret("internal").expect("generate");
        assert!(value.starts_with("dummy_internal_"));
    }
}
