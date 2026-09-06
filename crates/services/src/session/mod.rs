//! A paired lockdownd session shared by every normal-mode service. Reading
//! validates an existing pairing; only NormalDevice::pair creates a pairing.

use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use idevice::{Idevice, pairing_file::PairingFile};
use plist::{Dictionary, Value};
use zeroize::Zeroize;

use crate::{NormalDevice, RawServiceConnection, ServiceError, plist_service::PropertyListService};

#[cfg(feature = "legacy-tls")]
mod legacy_tls;
#[cfg(feature = "legacy-tls")]
pub use legacy_tls::LegacyTlsError;

const LABEL: &str = "legacy-ios-kit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlsProfile {
    validate_pair: bool,
    legacy_tls: bool,
}

impl TlsProfile {
    fn for_version(version: &str) -> Result<Self, ServiceError> {
        let major = version
            .split('.')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value >= 2)
            .ok_or(ServiceError::UnexpectedValue("ProductVersion"))?;
        Ok(Self {
            validate_pair: major < 7,
            legacy_tls: major < 10,
        })
    }
}

struct Credentials(PairingFile);
impl Drop for Credentials {
    fn drop(&mut self) {
        self.0.root_private_key.zeroize();
        self.0.host_private_key.zeroize();
        if let Some(escrow) = &mut self.0.escrow_bag {
            escrow.zeroize();
        }
    }
}

/// An authenticated connection using the device's existing pairing record.
/// Supports batching GetValue calls without repeated handshakes. Call close
/// when finished; dropping the session also closes its underlying socket.
pub struct DeviceSession {
    channel: PropertyListService<RawServiceConnection>,
    credentials: Credentials,
    profile: TlsProfile,
    session_id: String,
}

impl fmt::Debug for DeviceSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSession")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl DeviceSession {
    pub(crate) async fn open(device: &NormalDevice) -> Result<Self, ServiceError> {
        let connection = device.connect_port(62078).await?;
        let mut channel = PropertyListService::new(connection);
        let version = get_value(&mut channel, Some("ProductVersion"), None).await?;
        let profile = TlsProfile::for_version(
            version
                .as_string()
                .ok_or(ServiceError::UnexpectedValue("ProductVersion"))?,
        )?;
        #[cfg(not(feature = "legacy-tls"))]
        if profile.legacy_tls {
            return Err(ServiceError::LegacyTlsUnavailable);
        }
        let credentials = Credentials(device.pairing_file().await?);
        if profile.validate_pair {
            let mut validation = request("ValidatePair");
            validation.insert("ProtocolVersion".into(), "2".into());
            validation.insert(
                "PairRecord".into(),
                public_pair_record(&credentials.0).into(),
            );
            exchange(&mut channel, "ValidatePair", validation).await?;
        }
        let mut start = request("StartSession");
        start.insert("HostID".into(), credentials.0.host_id.clone().into());
        start.insert(
            "SystemBUID".into(),
            credentials.0.system_buid.clone().into(),
        );
        let response = exchange(&mut channel, "StartSession", start).await?;
        let session_id = response
            .get("SessionID")
            .and_then(Value::as_string)
            .ok_or(ServiceError::UnexpectedValue("SessionID"))?
            .to_owned();
        let secure = response
            .get("EnableSessionSSL")
            .and_then(Value::as_boolean)
            .ok_or(ServiceError::UnexpectedValue("EnableSessionSSL"))?;
        if secure {
            channel = PropertyListService::new(
                upgrade(channel.into_inner(), &credentials.0, profile).await?,
            );
        }
        Ok(Self {
            channel,
            credentials,
            profile,
            session_id,
        })
    }

    pub async fn get_value(
        &mut self,
        key: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Value, ServiceError> {
        get_value(&mut self.channel, key, domain).await
    }

    pub(crate) async fn service(
        &mut self,
        device: &NormalDevice,
        identifier: &str,
    ) -> Result<RawServiceConnection, ServiceError> {
        let mut start = request("StartService");
        start.insert("Service".into(), identifier.into());
        let response = exchange(&mut self.channel, "StartService", start).await?;
        let port = response
            .get("Port")
            .and_then(Value::as_unsigned_integer)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or(ServiceError::UnexpectedValue("Port"))?;
        let mut connection = device.connect_port(port).await?;
        if response
            .get("EnableServiceSSL")
            .and_then(Value::as_boolean)
            .unwrap_or(false)
        {
            connection = upgrade(connection, &self.credentials.0, self.profile).await?;
        }
        Ok(connection)
    }

    pub async fn close(mut self) -> Result<(), ServiceError> {
        let mut stop = request("StopSession");
        stop.insert("SessionID".into(), self.session_id.clone().into());
        tokio::time::timeout(
            Duration::from_secs(2),
            exchange(&mut self.channel, "StopSession", stop),
        )
        .await
        .map_err(|_| ServiceError::SessionTimeout)??;
        Ok(())
    }
}

pub(crate) async fn unpaired_values(
    device: &NormalDevice,
    keys: &[&str],
) -> Result<Dictionary, ServiceError> {
    let mut channel = PropertyListService::new(device.connect_port(62078).await?);
    let mut values = Dictionary::new();
    for key in keys {
        values.insert(
            (*key).into(),
            get_value(&mut channel, Some(key), None).await?,
        );
    }
    Ok(values)
}

async fn upgrade(
    connection: RawServiceConnection,
    pairing: &PairingFile,
    profile: TlsProfile,
) -> Result<RawServiceConnection, ServiceError> {
    if profile.legacy_tls {
        #[cfg(feature = "legacy-tls")]
        {
            return Ok(RawServiceConnection::new(
                legacy_tls::connect(Box::new(connection), pairing, profile).await?,
            ));
        }
        #[cfg(not(feature = "legacy-tls"))]
        {
            return Err(ServiceError::LegacyTlsUnavailable);
        }
    }
    let mut connection = Idevice::new(Box::new(connection), LABEL);
    connection.start_session(pairing, false).await?;
    Ok(RawServiceConnection::new(
        connection.get_socket().ok_or(ServiceError::MissingSocket)?,
    ))
}

fn public_pair_record(pairing: &PairingFile) -> Dictionary {
    let mut record = Dictionary::new();
    for (name, bytes) in [
        ("DeviceCertificate", &pairing.device_certificate),
        ("HostCertificate", &pairing.host_certificate),
        ("RootCertificate", &pairing.root_certificate),
    ] {
        let encoded = STANDARD.encode(bytes.as_ref());
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        record.insert(name.into(), Value::Data(pem.into_bytes()));
    }
    record.insert("HostID".into(), pairing.host_id.clone().into());
    record.insert("SystemBUID".into(), pairing.system_buid.clone().into());
    record
}

fn request(name: &str) -> Dictionary {
    Dictionary::from_iter([
        ("Label", Value::String(LABEL.into())),
        ("Request", Value::String(name.into())),
    ])
}

async fn get_value(
    channel: &mut PropertyListService<RawServiceConnection>,
    key: Option<&str>,
    domain: Option<&str>,
) -> Result<Value, ServiceError> {
    let mut query = request("GetValue");
    if let Some(key) = key {
        query.insert("Key".into(), key.into());
    }
    if let Some(domain) = domain {
        query.insert("Domain".into(), domain.into());
    }
    exchange(channel, "GetValue", query)
        .await?
        .remove("Value")
        .ok_or(ServiceError::UnexpectedValue("Value"))
}

async fn exchange(
    channel: &mut PropertyListService<RawServiceConnection>,
    expected: &'static str,
    request: Dictionary,
) -> Result<Dictionary, ServiceError> {
    channel.send(&request).await?;
    let response = channel.receive().await?;
    if let Some(error) = response.get("Error") {
        return Err(ServiceError::LockdownRejected {
            request: expected,
            code: error
                .as_string()
                .ok_or(ServiceError::UnexpectedValue("Error"))?
                .to_owned(),
        });
    }
    if response.get("Request").and_then(Value::as_string) != Some(expected) {
        return Err(ServiceError::UnexpectedValue("Request"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn protocol_boundaries_follow_legacy_lockdownd() {
        assert_eq!(
            TlsProfile::for_version("6.1.6").unwrap(),
            TlsProfile {
                validate_pair: true,
                legacy_tls: true
            }
        );
        assert_eq!(
            TlsProfile::for_version("7.0").unwrap(),
            TlsProfile {
                validate_pair: false,
                legacy_tls: true
            }
        );
        assert_eq!(
            TlsProfile::for_version("9.3.6").unwrap(),
            TlsProfile {
                validate_pair: false,
                legacy_tls: true
            }
        );
        assert_eq!(
            TlsProfile::for_version("10.0").unwrap(),
            TlsProfile {
                validate_pair: false,
                legacy_tls: false
            }
        );
        assert!(TlsProfile::for_version("unknown").is_err());
    }

    #[test]
    fn validation_never_serializes_private_keys_or_escrow_material() {
        let pairing = PairingFile {
            device_certificate: vec![1, 2, 3].into(),
            host_certificate: vec![4, 5, 6].into(),
            root_certificate: vec![7, 8, 9].into(),
            host_private_key: b"private host material".to_vec(),
            root_private_key: b"private root material".to_vec(),
            escrow_bag: Some(b"escrow material".to_vec()),
            host_id: "host".into(),
            system_buid: "buid".into(),
            wifi_mac_address: String::new(),
            udid: None,
        };
        let public = public_pair_record(&pairing);
        let mut names: Vec<_> = public.keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "DeviceCertificate",
                "HostCertificate",
                "HostID",
                "RootCertificate",
                "SystemBUID"
            ]
        );
        let pem = std::str::from_utf8(public["DeviceCertificate"].as_data().unwrap()).unwrap();
        assert_eq!(
            pem,
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        );
    }

    #[tokio::test]
    async fn a_rejected_pairing_is_an_error_not_an_implicit_repair() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let length = peer.read_u32().await.unwrap();
            let mut bytes = vec![0; length as usize];
            peer.read_exact(&mut bytes).await.unwrap();
            let request = Value::from_reader(std::io::Cursor::new(bytes)).unwrap();
            assert_eq!(
                request.as_dictionary().unwrap()["Request"].as_string(),
                Some("ValidatePair")
            );
            let reply = Value::Dictionary(Dictionary::from_iter([
                ("Request", Value::String("ValidatePair".into())),
                ("Error", Value::String("InvalidHostID".into())),
            ]));
            let mut bytes = vec![];
            reply.to_writer_xml(&mut bytes).unwrap();
            peer.write_u32(bytes.len() as u32).await.unwrap();
            peer.write_all(&bytes).await.unwrap();
        });
        let mut channel = PropertyListService::new(RawServiceConnection::new(Box::new(client)));
        assert!(
            matches!(exchange(&mut channel, "ValidatePair", request("ValidatePair")).await, Err(ServiceError::LockdownRejected { code, .. }) if code == "InvalidHostID")
        );
        server.await.unwrap();
    }
}
