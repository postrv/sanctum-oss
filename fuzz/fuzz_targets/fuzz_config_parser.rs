#![no_main]
use libfuzzer_sys::fuzz_target;
use sanctum_types::config::SanctumConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(toml_str) = std::str::from_utf8(data) {
        // Must never panic on any input, even malformed TOML
        let _ = toml::from_str::<SanctumConfig>(toml_str);
    }
});
