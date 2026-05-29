use std::sync::{Arc, OnceLock};

use tracing::warn;

static SHARED_TLS_CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();

/// Build a process-wide rustls config used by every reqwest client.
///
/// System trust roots are preferred, but when none are available (e.g. inside
/// a packaging/build sandbox) we fall back to the bundled Mozilla roots from
/// `webpki-roots`. This keeps client construction infallible w.r.t. missing CA
/// stores, so we never hit reqwest's panicking `Client::new()` path.
pub(crate) fn shared_tls_config() -> Option<Arc<rustls::ClientConfig>> {
    SHARED_TLS_CONFIG
        .get_or_init(|| build_rustls_config().map(Arc::new))
        .clone()
}

pub(crate) fn build_rustls_config() -> Option<rustls::ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let mut root_store = rustls::RootCertStore::empty();

    let cert_result = rustls_native_certs::load_native_certs();
    if !cert_result.errors.is_empty() {
        let details = cert_result
            .errors
            .iter()
            .take(3)
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        warn!(
            errors = cert_result.errors.len(),
            details = %details,
            "failed to load native certificates"
        );
    }

    for cert in cert_result.certs {
        let _ = root_store.add(cert);
    }

    if root_store.is_empty() {
        // No system trust store (e.g. build sandbox): fall back to bundled Mozilla roots.
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = rustls::ClientConfig::builder_with_provider(provider.into());
    let builder = match builder.with_safe_default_protocol_versions() {
        Ok(builder) => builder,
        Err(e) => {
            warn!(
                error = %e,
                "failed to configure rustls protocol versions; falling back to reqwest default TLS"
            );
            return None;
        }
    };

    Some(
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rustls_config_does_not_panic() {
        let _ = build_rustls_config();
    }

    #[test]
    fn shared_tls_config_is_available() {
        // Native roots or the webpki-roots fallback must always yield a config.
        assert!(shared_tls_config().is_some());
    }
}
