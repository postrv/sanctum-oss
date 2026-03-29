//! Certificate Authority management for MITM TLS interception.
//!
//! Generates and manages a local CA certificate used to sign per-host
//! certificates for LLM API endpoints. The CA private key is stored
//! with restrictive file permissions (0o600) and is never logged.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::ProxyError;

/// A local Certificate Authority for generating per-host TLS certificates.
#[allow(clippy::struct_field_names)]
pub struct CertificateAuthority {
    /// The signed CA certificate (used for signing site certs).
    cert: rcgen::Certificate,
    /// The CA key pair.
    key: KeyPair,
    /// The DER-encoded CA certificate (for distribution to clients).
    cert_der: CertificateDer<'static>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("cert", &"<Certificate>")
            .field("key", &"<KeyPair>")
            .field("cert_der", &format!("[{} bytes]", self.cert_der.len()))
            .finish()
    }
}

impl CertificateAuthority {
    /// Generate a new self-signed CA certificate.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaGeneration` if key or certificate generation fails.
    pub fn generate(validity_days: u32) -> Result<Self, ProxyError> {
        let key_pair = KeyPair::generate().map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to generate CA key pair: {e}"),
        })?;

        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| {
            ProxyError::CaGeneration {
                reason: format!("failed to create CA params: {e}"),
            }
        })?;

        params
            .distinguished_name
            .push(DnType::CommonName, "Sanctum Local CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sanctum");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        // Set validity period.
        // validity_days is clamped to 1..=3650 by config, so years fits in i32.
        // Clamp to 10 to be safe even if config validation is bypassed.
        let years_u32 = (validity_days / 365).min(10);
        #[allow(clippy::cast_possible_wrap)]
        let years = years_u32 as i32;
        let not_before = rcgen::date_time_ymd(2024, 1, 1);
        let not_after = rcgen::date_time_ymd(2024 + years + 1, 1, 1);
        params.not_before = not_before;
        params.not_after = not_after;

        let signed_cert = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::CaGeneration {
                reason: format!("failed to self-sign CA certificate: {e}"),
            })?;

        let der = CertificateDer::from(signed_cert.der().to_vec());

        Ok(Self {
            cert: signed_cert,
            key: key_pair,
            cert_der: der,
        })
    }

    /// Load a CA from PEM-encoded key and certificate files on disk.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaKeyFile` if files cannot be read.
    /// Returns `ProxyError::CaGeneration` if parsing fails.
    pub fn load(key_path: &Path, cert_path: &Path) -> Result<Self, ProxyError> {
        let key_pem = std::fs::read_to_string(key_path).map_err(|source| {
            ProxyError::CaKeyFile { source }
        })?;
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|source| {
            ProxyError::CaKeyFile { source }
        })?;

        let key_pair = KeyPair::from_pem(&key_pem).map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to parse CA key: {e}"),
        })?;

        let params =
            CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| {
                ProxyError::CaGeneration {
                    reason: format!("failed to parse CA cert params: {e}"),
                }
            })?;

        let signed_cert =
            params
                .self_signed(&key_pair)
                .map_err(|e| ProxyError::CaGeneration {
                    reason: format!("failed to re-sign loaded CA: {e}"),
                })?;

        let der = CertificateDer::from(signed_cert.der().to_vec());

        Ok(Self {
            cert: signed_cert,
            key: key_pair,
            cert_der: der,
        })
    }

    /// Save the CA key and certificate to disk in PEM format.
    ///
    /// The key file is created with restrictive permissions (0o600 on Unix).
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaKeyFile` if file operations fail.
    pub fn save(&self, key_path: &Path, cert_path: &Path) -> Result<(), ProxyError> {
        // Ensure parent directories exist.
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ProxyError::CaKeyFile { source })?;
        }
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ProxyError::CaKeyFile { source })?;
        }

        // Write key with restrictive permissions.
        let key_pem = self.key.serialize_pem();
        std::fs::write(key_path, key_pem.as_bytes())
            .map_err(|source| ProxyError::CaKeyFile { source })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(key_path, perms)
                .map_err(|source| ProxyError::CaKeyFile { source })?;
        }

        // Write certificate.
        let cert_pem = self.cert.pem();
        std::fs::write(cert_path, cert_pem.as_bytes())
            .map_err(|source| ProxyError::CaKeyFile { source })?;

        Ok(())
    }

    /// Generate a TLS certificate for a specific domain, signed by this CA.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaGeneration` if certificate generation fails.
    pub fn generate_site_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ProxyError> {
        let site_key =
            KeyPair::generate().map_err(|e| ProxyError::CaGeneration {
                reason: format!("failed to generate site key for {domain}: {e}"),
            })?;

        let mut params = CertificateParams::new(vec![domain.to_owned()]).map_err(|e| {
            ProxyError::CaGeneration {
                reason: format!("failed to create site cert params for {domain}: {e}"),
            }
        })?;

        params
            .distinguished_name
            .push(DnType::CommonName, domain);
        params.is_ca = IsCa::NoCa;

        let site_cert = params
            .signed_by(&site_key, &self.cert, &self.key)
            .map_err(|e| ProxyError::CaGeneration {
                reason: format!("failed to sign site cert for {domain}: {e}"),
            })?;

        let cert_der = CertificateDer::from(site_cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(site_key.serialize_der()));

        Ok((cert_der, key_der))
    }

    /// Get the DER-encoded CA certificate for distribution.
    #[must_use]
    pub const fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Get the PEM-encoded CA certificate as a string.
    #[must_use]
    pub fn ca_cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// Default CA key file path within the Sanctum data directory.
    #[must_use]
    pub fn default_key_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("ca").join("sanctum-ca.key")
    }

    /// Default CA certificate file path within the Sanctum data directory.
    #[must_use]
    pub fn default_cert_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("ca").join("sanctum-ca.pem")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let ca = CertificateAuthority::generate(365);
        assert!(ca.is_ok(), "CA generation should succeed");
        let ca = ca.unwrap();
        assert!(!ca.ca_cert_der().is_empty(), "CA cert should not be empty");
    }

    #[test]
    fn test_generate_and_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("ca.key");
        let cert_path = dir.path().join("ca.pem");

        let ca = CertificateAuthority::generate(365).expect("generate CA");
        ca.save(&key_path, &cert_path).expect("save CA");

        // Verify key file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).expect("key metadata");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file should have 0o600 permissions");
        }

        // Verify files exist.
        assert!(key_path.exists(), "key file should exist");
        assert!(cert_path.exists(), "cert file should exist");

        // Load and verify.
        let loaded = CertificateAuthority::load(&key_path, &cert_path);
        assert!(loaded.is_ok(), "loading saved CA should succeed");
    }

    #[test]
    fn test_generate_site_cert() {
        let ca = CertificateAuthority::generate(365).expect("generate CA");
        let result = ca.generate_site_cert("api.openai.com");
        assert!(result.is_ok(), "site cert generation should succeed");
        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty(), "site cert should not be empty");
        assert!(
            !matches!(key_der, PrivateKeyDer::Pkcs8(ref k) if k.secret_pkcs8_der().is_empty()),
            "site key should not be empty"
        );
    }

    #[test]
    fn test_generate_site_cert_multiple_domains() {
        let ca = CertificateAuthority::generate(365).expect("generate CA");
        let domains = ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"];
        for domain in domains {
            let result = ca.generate_site_cert(domain);
            assert!(result.is_ok(), "site cert for {domain} should succeed");
        }
    }

    #[test]
    fn test_default_paths() {
        let data_dir = std::path::Path::new("/tmp/sanctum-test");
        let key_path = CertificateAuthority::default_key_path(data_dir);
        let cert_path = CertificateAuthority::default_cert_path(data_dir);
        assert!(key_path.ends_with("ca/sanctum-ca.key"));
        assert!(cert_path.ends_with("ca/sanctum-ca.pem"));
    }

    #[test]
    fn test_ca_cert_pem_not_empty() {
        let ca = CertificateAuthority::generate(365).expect("generate CA");
        let pem = ca.ca_cert_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"), "PEM should contain certificate header");
        assert!(pem.contains("END CERTIFICATE"), "PEM should contain certificate footer");
    }

    #[test]
    fn test_load_nonexistent_key_returns_error() {
        let result = CertificateAuthority::load(
            Path::new("/nonexistent/ca.key"),
            Path::new("/nonexistent/ca.pem"),
        );
        assert!(result.is_err(), "loading nonexistent key should fail");
        assert!(
            matches!(result.unwrap_err(), ProxyError::CaKeyFile { .. }),
            "should be a CaKeyFile error"
        );
    }

    #[test]
    fn test_save_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("nested").join("deep").join("ca.key");
        let cert_path = dir.path().join("nested").join("deep").join("ca.pem");

        let ca = CertificateAuthority::generate(365).expect("generate CA");
        let result = ca.save(&key_path, &cert_path);
        assert!(result.is_ok(), "save should create parent dirs");
        assert!(key_path.exists(), "key file should exist");
        assert!(cert_path.exists(), "cert file should exist");
    }
}
