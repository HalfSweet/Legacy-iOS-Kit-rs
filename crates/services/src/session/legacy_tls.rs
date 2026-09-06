//! Optional TLS 1.0 compatibility for a paired USB device. Never used for HTTP.
use super::TlsProfile;
use idevice::{ReadWrite, pairing_file::PairingFile};
use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::X509,
};
use std::pin::Pin;

#[derive(Debug, thiserror::Error)]
pub enum LegacyTlsError {
    #[error("paired TLS identity is invalid")]
    Identity(#[from] openssl::error::ErrorStack),
    #[error("paired TLS handshake failed")]
    Handshake(#[from] openssl::ssl::Error),
    #[error("paired TLS stream failed")]
    Io(#[from] std::io::Error),
}
pub(super) async fn connect(
    stream: Box<dyn ReadWrite>,
    pairing: &PairingFile,
    policy: TlsProfile,
) -> Result<Box<dyn ReadWrite>, LegacyTlsError> {
    let mut connector = SslConnector::builder(SslMethod::tls_client())?;
    if policy.legacy_tls {
        // Old iOS lockdownd requires RSA/CBC suites and TLS 1.0. These settings
        // are scoped to this USB session, never to HTTP or host-wide TLS policy.
        connector.set_min_proto_version(Some(SslVersion::TLS1))?;
        connector.set_max_proto_version(Some(SslVersion::TLS1))?;
        connector.set_security_level(0);
        connector.set_cipher_list("AES128-SHA:AES256-SHA")?;
        connector.set_options(
            SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION
                | SslOptions::NO_RENEGOTIATION
                | SslOptions::IGNORE_UNEXPECTED_EOF,
        );
    }
    // libimobiledevice authenticates with the pairing root identity.
    let certificate = X509::from_der(pairing.root_certificate.as_ref())?;
    connector.set_certificate(&certificate)?;
    let key = if pairing.root_private_key.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem(&pairing.root_private_key)?
    } else {
        PKey::private_key_from_der(&pairing.root_private_key)?
    };
    connector.set_private_key(&key)?;
    connector.check_private_key()?;
    let expected = pairing.device_certificate.as_ref().to_vec();
    connector.set_verify_callback(SslVerifyMode::PEER, move |_, context| {
        if context.error_depth() != 0 {
            return true;
        }
        context
            .current_cert()
            .and_then(|certificate| certificate.to_der().ok())
            .is_some_and(|certificate| certificate == expected)
    });
    let mut configuration = connector.build().configure()?;
    configuration.set_use_server_name_indication(false);
    // iOS pairing certificates have no DNS hostname. The callback pins the
    // exact device certificate from the previously established pairing.
    configuration.set_verify_hostname(false);
    let ssl = configuration.into_ssl("Device")?;
    let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).connect().await?;
    tracing::debug!(
        protocol = stream.ssl().version_str(),
        "established paired USB TLS session"
    );
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::Private,
        rsa::Rsa,
        ssl::{Ssl, SslContext},
        x509::X509NameBuilder,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn certificate(name: &str) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&subject).unwrap();
        builder.set_issuer_name(&subject).unwrap();
        builder.set_pubkey(&key).unwrap();
        let before = Asn1Time::days_from_now(0).unwrap();
        let after = Asn1Time::days_from_now(1).unwrap();
        builder.set_not_before(&before).unwrap();
        builder.set_not_after(&after).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn identity(device: &X509) -> PairingFile {
        let (root, key) = certificate("test pairing root");
        PairingFile {
            device_certificate: device.to_der().unwrap().into(),
            host_private_key: b"unused-host-private-key".to_vec(),
            host_certificate: root.to_der().unwrap().into(),
            root_private_key: key.private_key_to_pem_pkcs8().unwrap(),
            root_certificate: root.to_der().unwrap().into(),
            system_buid: "test-buid".into(),
            host_id: "test-host".into(),
            escrow_bag: Some(b"test-escrow-secret".to_vec()),
            wifi_mac_address: String::new(),
            udid: None,
        }
    }

    fn tls_server(certificate: &X509, key: &PKey<Private>, expected_client: Vec<u8>) -> Ssl {
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context.set_security_level(0);
        context
            .set_min_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        context
            .set_max_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        context.set_cipher_list("AES128-SHA").unwrap();
        context.set_certificate(certificate).unwrap();
        context.set_private_key(key).unwrap();
        context.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |_, ctx| {
                ctx.current_cert()
                    .and_then(|cert| cert.to_der().ok())
                    .is_some_and(|cert| cert == expected_client)
            },
        );
        Ssl::new(&context.build()).unwrap()
    }

    #[tokio::test]
    async fn legacy_tls_authenticates_both_paired_identities() {
        let (device, key) = certificate("test device");
        let pair = identity(&device);
        let ssl = tls_server(&device, &key, pair.root_certificate.as_ref().to_vec());
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut stream = tokio_openssl::SslStream::new(ssl, server).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();
            assert_eq!(stream.ssl().version_str(), "TLSv1");
            stream.write_all(b"paired").await.unwrap();
        });
        let mut stream = connect(
            Box::new(client),
            &pair,
            TlsProfile::for_version("6.1.6").unwrap(),
        )
        .await
        .unwrap();
        let mut message = [0; 6];
        stream.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"paired");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn legacy_tls_rejects_a_different_device_certificate() {
        let (device, key) = certificate("other device");
        let (expected, _) = certificate("paired device");
        let pair = identity(&expected);
        let ssl = tls_server(&device, &key, pair.root_certificate.as_ref().to_vec());
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut stream = tokio_openssl::SslStream::new(ssl, server).unwrap();
            let _ = Pin::new(&mut stream).accept().await;
        });
        assert!(matches!(
            connect(
                Box::new(client),
                &pair,
                TlsProfile::for_version("6.1.6").unwrap()
            )
            .await,
            Err(LegacyTlsError::Handshake(_))
        ));
        peer.await.unwrap();
    }
}
