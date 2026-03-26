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
pub fn shannon_entropy(s: &str) -> f64 {
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
}
