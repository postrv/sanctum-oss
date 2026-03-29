//! Shannon entropy calculator.
//!
//! Computes the information entropy of strings to identify potential secrets
//! that do not match any known credential pattern. High-entropy strings
//! (typically > 4.5 bits/char) that are mostly alphanumeric are likely
//! randomly-generated secrets.

use std::collections::HashMap;

/// Compute the Shannon entropy of a string in bits per character.
///
/// Returns 0.0 for empty strings. The theoretical maximum for printable ASCII
/// is approximately 6.57 bits/char.
#[must_use]
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    let len = s.len() as f64;
    let mut freq: HashMap<u8, usize> = HashMap::new();

    for &byte in s.as_bytes() {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let mut entropy = 0.0_f64;
    for &count in freq.values() {
        #[allow(clippy::cast_precision_loss)]
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Determine whether a string is likely a high-entropy secret.
///
/// A string is considered a potential secret if:
/// 1. Its length is at least `min_length`.
/// 2. Its Shannon entropy exceeds `threshold`.
/// 3. At least 70% of its characters are alphanumeric.
#[must_use]
pub fn is_high_entropy_secret(s: &str, threshold: f64, min_length: usize) -> bool {
    if s.len() < min_length {
        return false;
    }

    // Check that the string is mostly alphanumeric (at least 70%)
    let alnum_count = s.chars().filter(|c| c.is_alphanumeric()).count();
    let total_count = s.chars().count();

    if total_count == 0 {
        return false;
    }

    #[allow(clippy::cast_precision_loss)]
    let alnum_ratio = alnum_count as f64 / total_count as f64;
    if alnum_ratio < 0.7 {
        return false;
    }

    shannon_entropy(s) > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        let result = shannon_entropy("");
        assert!((result - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn repeated_character_has_zero_entropy() {
        let result = shannon_entropy("aaaaaaaaaa");
        assert!((result - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn two_equal_chars_have_one_bit_entropy() {
        // "ab" with equal frequency: -2*(0.5 * log2(0.5)) = 1.0
        let result = shannon_entropy("ab");
        assert!((result - 1.0).abs() < 0.001);
    }

    #[test]
    fn random_looking_string_has_high_entropy() {
        // A string with many distinct characters should have high entropy
        let random_str = "aB3dE7fG9hJ2kL5mN8pQ1rS4tU6vW0xY";
        let entropy = shannon_entropy(random_str);
        assert!(
            entropy > 4.0,
            "Random-looking string should have entropy > 4.0, got {entropy}"
        );
    }

    #[test]
    fn english_text_has_moderate_entropy() {
        let text = "the quick brown fox jumps over the lazy dog";
        let entropy = shannon_entropy(text);
        // English text typically has 3.5-4.5 bits per character
        assert!(
            entropy > 2.0 && entropy < 5.0,
            "English text should have moderate entropy, got {entropy}"
        );
    }

    #[test]
    fn is_high_entropy_secret_rejects_short_strings() {
        assert!(!is_high_entropy_secret("abc", 4.5, 20));
    }

    #[test]
    fn is_high_entropy_secret_rejects_low_entropy() {
        let repeated = "a".repeat(30);
        assert!(!is_high_entropy_secret(&repeated, 4.5, 20));
    }

    #[test]
    fn is_high_entropy_secret_accepts_random_string() {
        // Construct a high-entropy alphanumeric string
        let secret = "aB3dE7fG9hJ2kL5mN8pQ1rS4tU6vW0x";
        assert!(is_high_entropy_secret(secret, 4.0, 20));
    }

    #[test]
    fn is_high_entropy_secret_rejects_non_alphanumeric() {
        // A string that is mostly punctuation/special chars
        let special = "!@#$%^&*()_+-=[]{}|;':,./<>?~`!!";
        assert!(!is_high_entropy_secret(special, 3.0, 10));
    }

    #[test]
    fn entropy_is_deterministic() {
        let s = "test_string_for_determinism";
        let e1 = shannon_entropy(s);
        let e2 = shannon_entropy(s);
        assert!(
            (e1 - e2).abs() < 1e-10,
            "Entropy should be deterministic: {e1} vs {e2}"
        );
    }

    // ---- Boundary tests ----

    #[test]
    fn exact_min_length_high_entropy_detected() {
        // 20 unique alphanumeric chars — max entropy for 20 unique bytes is log2(20) ≈ 4.32.
        // Use a threshold just below that so the string is detected as a secret.
        let s = "aB3dE7fG9hJ2kL5mN8pQ";
        assert_eq!(s.len(), 20);
        let entropy = shannon_entropy(s);
        assert!(
            entropy > 4.0,
            "Expected entropy > 4.0 for 20 unique chars, got {entropy}"
        );
        // With a threshold just below the actual entropy, it should be detected
        assert!(is_high_entropy_secret(s, entropy - 0.1, 20));
        // With a threshold above the actual entropy, it should not be detected
        assert!(!is_high_entropy_secret(s, entropy + 0.1, 20));
    }

    #[test]
    fn exactly_seventy_percent_alphanumeric_boundary() {
        // 20-char string with exactly 14 alphanumeric (70%) and 6 non-alphanumeric
        // 14 unique alnum + 6 unique non-alnum = 20 unique bytes → entropy = log2(20) ≈ 4.32
        let s = "aB3dE7fG9hJ2kL!@#$%^";
        assert_eq!(s.len(), 20);
        let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
        let total = s.chars().count();
        assert_eq!(alnum, 14);
        assert_eq!(total, 20);
        // 14/20 = 0.70 — exactly at the boundary
        // The code uses `< 0.7` (strict less-than), so exactly 0.70 should pass
        let entropy = shannon_entropy(s);
        assert!(is_high_entropy_secret(s, entropy - 0.1, 20));
    }

    #[test]
    fn multi_byte_utf8_handled_correctly() {
        // Multi-byte UTF-8: each char is 2+ bytes, so len() > chars().count().
        // The function uses len() for the min_length check but chars().count() for
        // the alphanumeric ratio. Verify it doesn't panic or produce wrong results.
        // "ÄÖÜäöüßÀÈÌ" — 11 chars, each 2 bytes = 22 bytes
        let s = "ÄÖÜäöüßÀÈÌÒ";
        assert!(
            s.len() > s.chars().count(),
            "byte length {} should exceed char count {}",
            s.len(),
            s.chars().count()
        );
        // These are alphabetic, so they pass the alphanumeric check.
        // With min_length = s.len(), the len() check passes (bytes >= min_length).
        // With min_length = s.len() + 1, it should fail.
        let entropy = shannon_entropy(s);
        assert!(is_high_entropy_secret(s, entropy - 0.1, s.len()));
        assert!(!is_high_entropy_secret(s, entropy - 0.1, s.len() + 1));
    }
}

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(10)]
    fn shannon_entropy_never_panics() {
        // Prove that shannon_entropy never panics for any input up to 8 bytes.
        let len: usize = kani::any();
        kani::assume(len <= 8);

        let bytes: [u8; 8] = kani::any();
        // Construct a valid UTF-8 string from the bytes
        if let Ok(s) = std::str::from_utf8(&bytes[..len]) {
            let result = shannon_entropy(s);
            // Entropy must be non-negative
            assert!(result >= 0.0, "entropy must be non-negative");
            // Empty string must have zero entropy
            if s.is_empty() {
                assert!(result == 0.0, "empty string must have zero entropy");
            }
            // Single-character repeated strings must have zero entropy
            if !s.is_empty() && s.bytes().all(|b| b == s.as_bytes()[0]) {
                assert!(result == 0.0, "uniform string must have zero entropy");
            }

            // Verify key paths are reachable
            kani::cover!(s.is_empty(), "empty string path reachable");
            kani::cover!(s.len() == 1, "single char path reachable");
            kani::cover!(s.len() >= 2, "multi char path reachable");
        }
    }
}
