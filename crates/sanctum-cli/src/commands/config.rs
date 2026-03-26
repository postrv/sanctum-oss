//! `sanctum config` — View or edit configuration.

use std::fs;
use std::path::PathBuf;

use sanctum_types::errors::CliError;

/// Run the config command.
pub fn run(edit: bool) -> Result<(), CliError> {
    let config_path = find_config_path();

    if edit {
        let editor = std::env::var("EDITOR")
            .or_else(|_| std::env::var("VISUAL"))
            .unwrap_or_else(|_| "vi".to_string());

        let path = if let Some(p) = config_path { p } else {
            // Create default config in standard location
            let paths = sanctum_types::paths::WellKnownPaths::default();
            let config_file = paths.config_dir.join("config.toml");
            fs::create_dir_all(&paths.config_dir)?;

            if !config_file.exists() {
                fs::write(&config_file, default_config())?;
            }
            config_file
        };

        #[allow(clippy::print_stdout)]
        {
            println!("Opening {} in {editor}...", path.display());
        }

        let status = std::process::Command::new(&editor)
            .arg(&path)
            .status()
            .map_err(|e| CliError::InvalidArgs(format!("failed to open editor '{editor}': {e}")))?;

        if !status.success() {
            return Err(CliError::InvalidArgs("editor exited with error".to_string()));
        }
    } else {
        match config_path {
            Some(path) => {
                let content = fs::read_to_string(&path)?;
                #[allow(clippy::print_stdout)]
                {
                    println!("Configuration: {}", path.display());
                    println!("{:-<72}", "");
                    println!("{content}");
                }
            }
            None => {
                #[allow(clippy::print_stdout)]
                {
                    println!("No configuration file found.");
                    println!();
                    println!("Run `sanctum init` to create one, or `sanctum config --edit` to create and edit.");
                    println!();
                    println!("Current defaults:");
                    println!("{:-<72}", "");
                    println!("{}", default_config());
                }
            }
        }
    }

    Ok(())
}

fn find_config_path() -> Option<PathBuf> {
    let local = PathBuf::from(".sanctum/config.toml");
    if local.exists() {
        return Some(local);
    }

    let paths = sanctum_types::paths::WellKnownPaths::default();
    let global = paths.config_dir.join("config.toml");
    if global.exists() {
        return Some(global);
    }

    None
}

const fn default_config() -> &'static str {
    r#"# Sanctum configuration
# https://sanctum.dev/docs/config

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = false
pth_response = "quarantine"

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[budgets]
# default_session = "$50"
# default_daily = "$200"
alert_at_percent = 75
"#
}
