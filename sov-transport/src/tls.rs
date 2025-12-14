use std::{fs::File, io::BufReader, sync::Arc};

use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub ca_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub server_name: Option<String>,
    pub require_mtls: bool,
}

fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let f = File::open(path)?;
    let mut r = BufReader::new(f);
    Ok(certs(&mut r)?.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &str) -> anyhow::Result<PrivateKey> {
    //
    {
        let f = File::open(path)?;
        let mut r = BufReader::new(f);
        if let Ok(mut keys) = pkcs8_private_keys(&mut r) {
            if let Some(k) = keys.pop() {
                return Ok(PrivateKey(k));
            }
        }
    }

    {
        let f = File::open(path)?;
        let mut r = BufReader::new(f);
        if let Ok(mut keys) = rsa_private_keys(&mut r) {
            if let Some(k) = keys.pop() {
                return Ok(PrivateKey(k));
            }
        }
    }

    anyhow::bail!("no private key found in {}", path)
}

fn load_ca_store(ca_path: &str) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca_path)? {
        roots.add(&c)?;
    }
    Ok(roots)
}

pub fn build_tls_acceptor(cfg: &TlsConfig) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;

    let server_cfg = if cfg.require_mtls {
        // mTLS: клиентский сертификат обязателен и должен быть подписан CA
        let roots = load_ca_store(&cfg.ca_path)?;
        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(certs, key)?
    } else {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

pub fn build_tls_connector(cfg: &TlsConfig) -> anyhow::Result<TlsConnector> {
    let roots = load_ca_store(&cfg.ca_path)?;

    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;

    let client_cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        // rustls 0.21: предпочитаемый метод
        .with_client_auth_cert(certs, key)?;

    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

pub fn extract_role_from_cert(cert: &Certificate) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, parsed) = X509Certificate::from_der(&cert.0).ok()?;
    // OU OID = 2.5.4.11
    for attr in parsed.subject().iter_attributes() {
        if attr.attr_type().to_id_string() == "2.5.4.11" {
            return attr.as_str().ok().map(|s| s.to_string());
        }
    }
    None
}
