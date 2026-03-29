#![no_main]
use libfuzzer_sys::fuzz_target;
use sanctum_sentinel::pth::analyser::analyse_pth_line;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        // Must never panic, regardless of input
        let _ = analyse_pth_line(line);
    }
});
