//! Certificate Authority (CA) management for MITM TLS interception.
//!
//! Generates and loads a local CA certificate used by the proxy to issue
//! per-site TLS certificates on the fly. The CA private key is stored with
//! restrictive file permissions (0o600) set atomically at creation time.

use std::path::Path;

use chrono::Utc;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::ProxyError;

/// A loaded CA identity (certificate + private key).
#[derive(Debug, Clone)]
pub struct CaIdentity {
    /// The CA certificate in DER format.
    pub cert_der: CertificateDer<'static>,
    /// The CA key DER bytes (stored as Vec for cloneability).
    pub key_der_bytes: Vec<u8>,
    /// The CA certificate in PEM format.
    pub cert_pem: String,
    /// The CA key in PEM format.
    pub key_pem: String,
}

impl CaIdentity {
    /// Get the private key as a `PrivateKeyDer`.
    #[must_use]
    pub fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der_bytes.clone()))
    }
}

/// Maximum allowed domain label length (RFC 1035).
const MAX_DOMAIN_LABEL_LEN: usize = 63;
/// Maximum allowed total domain length (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

/// Site certificate validity in hours (24 hours).
const SITE_CERT_VALIDITY_HOURS: i64 = 24;

/// Generate a new CA certificate and private key.
///
/// The certificate is valid from now until `now + validity_days`.
///
/// # Errors
///
/// Returns `ProxyError::CaGeneration` if certificate generation fails.
pub fn generate_ca(validity_days: u32) -> Result<CaIdentity, ProxyError> {
    let key_pair = KeyPair::generate().map_err(|e| ProxyError::CaGeneration {
        reason: format!("failed to generate CA key pair: {e}"),
    })?;

    let now = Utc::now();
    let not_before = rcgen::date_time_ymd(now.year(), now.month_u8(), now.day_u8());
    let not_after_date = now + chrono::Duration::days(i64::from(validity_days));
    let not_after = rcgen::date_time_ymd(
        not_after_date.year(),
        not_after_date.month_u8(),
        not_after_date.day_u8(),
    );

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Sanctum Proxy CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Sanctum");
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = params.self_signed(&key_pair).map_err(|e| {
        ProxyError::CaGeneration {
            reason: format!("failed to self-sign CA certificate: {e}"),
        }
    })?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der_bytes = key_pair.serialize_der();

    Ok(CaIdentity {
        cert_der,
        key_der_bytes,
        cert_pem,
        key_pem,
    })
}

/// Write the CA certificate and key to files.
///
/// The private key file is created with mode 0o600 (owner read/write only)
/// atomically via `OpenOptions` to prevent a TOCTOU race where another
/// process could read the key before permissions are set.
///
/// # Errors
///
/// Returns `ProxyError::CaKeyFile` if file operations fail.
pub fn write_ca_files(
    ca: &CaIdentity,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), ProxyError> {
    // Write the certificate (not secret, world-readable is fine).
    std::fs::write(cert_path, &ca.cert_pem).map_err(|e| ProxyError::CaKeyFile { source: e })?;

    // Write the private key with restrictive permissions atomically.
    write_key_file(key_path, &ca.key_pem)?;

    Ok(())
}

/// Write a private key file with 0o600 permissions set at creation time.
///
/// Uses `OpenOptionsExt::mode()` to set permissions atomically, avoiding
/// the TOCTOU race of write-then-chmod.
#[cfg(unix)]
fn write_key_file(path: &Path, content: &str) -> Result<(), ProxyError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| ProxyError::CaKeyFile { source: e })?;

    file.write_all(content.as_bytes())
        .map_err(|e| ProxyError::CaKeyFile { source: e })?;

    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, content: &str) -> Result<(), ProxyError> {
    std::fs::write(path, content).map_err(|e| ProxyError::CaKeyFile { source: e })?;
    Ok(())
}

/// Load a CA identity from PEM files on disk.
///
/// # Errors
///
/// Returns `ProxyError::CaKeyFile` if files cannot be read.
/// Returns `ProxyError::CaGeneration` if PEM parsing fails.
pub fn load_ca(cert_path: &Path, key_path: &Path) -> Result<CaIdentity, ProxyError> {
    let cert_pem =
        std::fs::read_to_string(cert_path).map_err(|e| ProxyError::CaKeyFile { source: e })?;
    let key_pem =
        std::fs::read_to_string(key_path).map_err(|e| ProxyError::CaKeyFile { source: e })?;

    let cert_params =
        CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to parse CA certificate PEM: {e}"),
        })?;

    // Parse the key pair from PEM to validate it.
    let key_pair = KeyPair::from_pem(&key_pem).map_err(|e| ProxyError::CaGeneration {
        reason: format!("failed to parse CA key PEM: {e}"),
    })?;

    // Validate that the loaded cert is still a CA (before consuming params).
    if !matches!(cert_params.is_ca, IsCa::Ca(_)) {
        return Err(ProxyError::CaGeneration {
            reason: "loaded certificate is not a CA certificate".to_string(),
        });
    }

    // Re-derive the certificate by self-signing the parsed params.
    let cert = cert_params.self_signed(&key_pair).map_err(|e| {
        ProxyError::CaGeneration {
            reason: format!("failed to reconstruct CA cert: {e}"),
        }
    })?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der_bytes = key_pair.serialize_der();

    Ok(CaIdentity {
        cert_der,
        key_der_bytes,
        cert_pem,
        key_pem,
    })
}

/// Validate that a domain name is syntactically valid.
///
/// Checks RFC 1035 constraints: max label length 63, max total length 253,
/// labels contain only alphanumeric chars and hyphens, no leading/trailing
/// hyphens.
fn validate_domain(domain: &str) -> Result<(), ProxyError> {
    if domain.is_empty() {
        return Err(ProxyError::CaGeneration {
            reason: "domain name is empty".to_string(),
        });
    }

    if domain.len() > MAX_DOMAIN_LEN {
        return Err(ProxyError::CaGeneration {
            reason: format!(
                "domain name too long ({} chars, max {MAX_DOMAIN_LEN})",
                domain.len()
            ),
        });
    }

    for label in domain.split('.') {
        if label.is_empty() {
            return Err(ProxyError::CaGeneration {
                reason: format!("domain '{domain}' has empty label"),
            });
        }
        if label.len() > MAX_DOMAIN_LABEL_LEN {
            return Err(ProxyError::CaGeneration {
                reason: format!(
                    "domain label '{label}' too long ({} chars, max {MAX_DOMAIN_LABEL_LEN})",
                    label.len()
                ),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProxyError::CaGeneration {
                reason: format!("domain label '{label}' has leading or trailing hyphen"),
            });
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(ProxyError::CaGeneration {
                reason: format!("domain label '{label}' contains invalid characters"),
            });
        }
    }

    Ok(())
}

/// Generate a site certificate signed by the CA for MITM interception.
///
/// The certificate is valid for 24 hours and includes:
/// - `KeyUsage: DigitalSignature`
/// - `ExtendedKeyUsage: ServerAuth`
/// - SAN: the domain name
///
/// # Errors
///
/// Returns `ProxyError::CaGeneration` if certificate generation fails or
/// the domain format is invalid.
pub fn generate_site_cert(
    ca: &CaIdentity,
    domain: &str,
) -> Result<(CertificateDer<'static>, Vec<u8>), ProxyError> {
    validate_domain(domain)?;

    let site_key = KeyPair::generate().map_err(|e| ProxyError::CaGeneration {
        reason: format!("failed to generate site key pair: {e}"),
    })?;

    let now = Utc::now();
    let not_before = rcgen::date_time_ymd(now.year(), now.month_u8(), now.day_u8());
    let not_after_date = now + chrono::Duration::hours(SITE_CERT_VALIDITY_HOURS);
    let not_after = rcgen::date_time_ymd(
        not_after_date.year(),
        not_after_date.month_u8(),
        not_after_date.day_u8(),
    );

    let mut params = CertificateParams::new(vec![domain.to_owned()]).map_err(|e| {
        ProxyError::CaGeneration {
            reason: format!("failed to create site cert params: {e}"),
        }
    })?;

    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_owned());
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .subject_alt_names
        .push(SanType::DnsName(domain.try_into().map_err(|e| {
            ProxyError::CaGeneration {
                reason: format!("invalid domain for SAN: {e}"),
            }
        })?));

    // Load CA key pair for signing.
    let ca_key = KeyPair::from_pem(&ca.key_pem).map_err(|e| ProxyError::CaGeneration {
        reason: format!("failed to parse CA key for signing: {e}"),
    })?;

    let ca_cert_params =
        CertificateParams::from_ca_cert_pem(&ca.cert_pem).map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to parse CA cert for signing: {e}"),
        })?;

    let ca_cert = ca_cert_params.self_signed(&ca_key).map_err(|e| {
        ProxyError::CaGeneration {
            reason: format!("failed to reconstruct CA cert for signing: {e}"),
        }
    })?;

    let site_cert = params
        .signed_by(&site_key, &ca_cert, &ca_key)
        .map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to sign site certificate: {e}"),
        })?;

    let cert_der = CertificateDer::from(site_cert.der().to_vec());
    let key_der_bytes = site_key.serialize_der();

    Ok((cert_der, key_der_bytes))
}

// --- Helper trait to get month/day/year as the types rcgen expects ---

trait DateComponents {
    fn month_u8(&self) -> u8;
    fn day_u8(&self) -> u8;
    fn year(&self) -> i32;
}

impl<Tz: chrono::TimeZone> DateComponents for chrono::DateTime<Tz> {
    fn month_u8(&self) -> u8 {
        use chrono::Datelike;
        // month() returns 1..=12, which always fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let m = self.month() as u8;
        m
    }

    fn day_u8(&self) -> u8 {
        use chrono::Datelike;
        // day() returns 1..=31, which always fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let d = self.day() as u8;
        d
    }

    fn year(&self) -> i32 {
        chrono::Datelike::year(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca_produces_valid_cert() {
        let ca = generate_ca(365).expect("CA generation should succeed");
        assert!(!ca.cert_pem.is_empty());
        assert!(!ca.key_pem.is_empty());
        assert!(!ca.cert_der.is_empty());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_generate_ca_cert_uses_current_date() {
        // The cert should be valid from today, not hardcoded to 2024.
        let ca = generate_ca(365).expect("CA generation should succeed");
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_write_and_load_ca_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");

        let original = generate_ca(365).expect("generate");
        write_ca_files(&original, &cert_path, &key_path).expect("write");

        let loaded = load_ca(&cert_path, &key_path).expect("load");

        // The PEM content should match.
        assert_eq!(original.cert_pem, loaded.cert_pem);
        assert_eq!(original.key_pem, loaded.key_pem);
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions_atomic() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");

        let ca = generate_ca(365).expect("generate");
        write_ca_files(&ca, &cert_path, &key_path).expect("write");

        let metadata = std::fs::metadata(&key_path).expect("metadata");
        let mode = metadata.mode() & 0o777;
        assert_eq!(mode, 0o600, "key file should have 0o600 permissions");
    }

    #[test]
    fn test_generate_site_cert_valid_domain() {
        let ca = generate_ca(365).expect("CA generation");
        let result = generate_site_cert(&ca, "api.openai.com");
        assert!(result.is_ok(), "site cert generation should succeed");
        let (cert_der, key_der_bytes) = result.unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der_bytes.is_empty());
    }

    #[test]
    fn test_generate_site_cert_empty_domain_rejected() {
        let ca = generate_ca(365).expect("CA generation");
        let result = generate_site_cert(&ca, "");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "error should mention empty: {err}"
        );
    }

    #[test]
    fn test_generate_site_cert_invalid_domain_rejected() {
        let ca = generate_ca(365).expect("CA generation");
        assert!(generate_site_cert(&ca, "-bad.com").is_err());
        assert!(generate_site_cert(&ca, "bad-.com").is_err());
        assert!(generate_site_cert(&ca, "bad domain.com").is_err());
        assert!(generate_site_cert(&ca, "bad..com").is_err());
    }

    #[test]
    fn test_generate_site_cert_long_domain_rejected() {
        let ca = generate_ca(365).expect("CA generation");
        let long_label = "a".repeat(64);
        let domain = format!("{long_label}.com");
        assert!(generate_site_cert(&ca, &domain).is_err());
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("api.openai.com").is_ok());
        assert!(validate_domain("sub-domain.example.org").is_ok());
        assert!(validate_domain("a.b.c.d.e").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("-bad.com").is_err());
        assert!(validate_domain("bad-.com").is_err());
        assert!(validate_domain("bad..com").is_err());
        assert!(validate_domain("bad domain.com").is_err());
    }
}
