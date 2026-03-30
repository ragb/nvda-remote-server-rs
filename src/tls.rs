use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tracing::info;

/// Load a TLS certificate chain and private key from PEM files.
///
/// The certificate file may contain multiple certificates (e.g. a leaf + intermediates
/// as in Let's Encrypt `fullchain.pem`). All certificates are returned so the server
/// presents the full chain during TLS handshake.
pub fn load_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read cert file: {cert_path}"))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("Failed to read key file: {key_path}"))?;

    let certs = parse_cert_chain(&cert_pem)
        .with_context(|| format!("Failed to parse certificates from {cert_path}"))?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {cert_path}");
    }
    info!(
        count = certs.len(),
        path = cert_path,
        "Loaded TLS certificate chain"
    );

    let key = parse_private_key(&key_pem)
        .with_context(|| format!("Failed to parse private key from {key_path}"))?;

    Ok((certs, key))
}

/// Generate a self-signed TLS certificate and save it to disk.
pub fn generate_and_save(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("Failed to write cert file: {cert_path}"))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("Failed to write key file: {key_path}"))?;

    info!("Self-signed TLS certificate generated and saved");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((vec![cert_der], key_der))
}

/// Parse all certificates from a PEM byte slice.
pub fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")
}

/// Parse the first PKCS8 private key from a PEM byte slice.
pub fn parse_private_key(pem: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>> {
    rustls_pemfile::pkcs8_private_keys(&mut &pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No PKCS8 private key found"))?
        .context("Failed to parse PKCS8 private key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_self_signed() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap()
    }

    #[test]
    fn parse_single_cert_from_pem() {
        let cert = generate_self_signed();
        let pem = cert.cert.pem();
        let certs = parse_cert_chain(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn parse_chain_from_concatenated_pem() {
        // Simulate a fullchain.pem with leaf + intermediate
        let leaf = generate_self_signed();
        let intermediate = generate_self_signed();
        let fullchain = format!("{}{}", leaf.cert.pem(), intermediate.cert.pem());
        let certs = parse_cert_chain(fullchain.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2, "Should parse both certs from chain PEM");
    }

    #[test]
    fn parse_empty_pem_returns_empty() {
        let certs = parse_cert_chain(b"").unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn parse_private_key_from_pem() {
        let cert = generate_self_signed();
        let key_pem = cert.signing_key.serialize_pem();
        let key = parse_private_key(key_pem.as_bytes());
        assert!(key.is_ok());
    }

    #[test]
    fn parse_private_key_from_empty_fails() {
        let key = parse_private_key(b"");
        assert!(key.is_err());
    }

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nvdaremote_tls_test_{name}"));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn load_from_files_reads_chain() {
        let dir = test_dir("chain");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        // Write a 2-cert chain
        let leaf = generate_self_signed();
        let intermediate = generate_self_signed();
        let fullchain = format!("{}{}", leaf.cert.pem(), intermediate.cert.pem());
        std::fs::write(&cert_path, &fullchain).unwrap();
        std::fs::write(&key_path, leaf.signing_key.serialize_pem()).unwrap();

        let (certs, _key) =
            load_from_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 2, "Should load full certificate chain");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_files_missing_cert_fails() {
        let result = load_from_files("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn generate_and_save_creates_files() {
        let dir = test_dir("generate");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        let (certs, _key) =
            generate_and_save(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify saved files are loadable
        let (loaded_certs, _) =
            load_from_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        assert_eq!(loaded_certs.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
