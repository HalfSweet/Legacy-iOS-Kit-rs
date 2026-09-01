//! Anisette data provisioning.
//!
//! Anisette headers are device-identity headers Apple requires on
//! authentication requests. Generating them locally needs Apple's ADI
//! library, which is not redistributable, so this crate fetches them from a
//! configurable HTTP endpoint speaking the AltServer/SideStore anisette
//! server protocol: a `GET` that returns the headers either as a JSON object
//! or as HTTP response headers.

use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;

/// Device-identity headers required by Apple's authentication services.
///
/// Never log the values; Apple treats them as device identifiers.
#[derive(Clone, Debug)]
pub struct AnisetteData {
    one_time_password: String,
    machine_id: String,
    local_user_id: String,
    routing_info: u64,
    device_unique_identifier: String,
    device_serial_number: String,
    device_description: String,
    client_time: String,
    locale: String,
    time_zone: String,
}

impl AnisetteData {
    /// `X-Apple-I-MD`
    pub fn one_time_password(&self) -> &str {
        &self.one_time_password
    }

    /// `X-Apple-I-MD-M`
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    /// `X-Apple-I-MD-LU`
    pub fn local_user_id(&self) -> &str {
        &self.local_user_id
    }

    /// `X-Apple-I-MD-RINFO`
    pub const fn routing_info(&self) -> u64 {
        self.routing_info
    }

    /// `X-Mme-Device-Id`
    pub fn device_unique_identifier(&self) -> &str {
        &self.device_unique_identifier
    }

    /// `X-Apple-I-SRL-NO`
    pub fn device_serial_number(&self) -> &str {
        &self.device_serial_number
    }

    /// `X-MMe-Client-Info`
    pub fn device_description(&self) -> &str {
        &self.device_description
    }

    /// `X-Apple-I-Client-Time`
    pub fn client_time(&self) -> &str {
        &self.client_time
    }

    /// `X-Apple-Locale`
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// `X-Apple-I-TimeZone`
    pub fn time_zone(&self) -> &str {
        &self.time_zone
    }

    /// Fixed fixture for protocol-construction tests.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            one_time_password: "otp".into(),
            machine_id: "machine".into(),
            local_user_id: "local-user".into(),
            routing_info: 17_106_176,
            device_unique_identifier: "DEVICE-ID".into(),
            device_serial_number: "SERIAL".into(),
            device_description: "desc".into(),
            client_time: "2024-01-01T00:00:00Z".into(),
            locale: "en_US".into(),
            time_zone: "UTC".into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AnisetteError {
    #[error("anisette request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("anisette endpoint returned {0}")]
    Status(reqwest::StatusCode),
    #[error("anisette response is missing {0}")]
    MissingField(&'static str),
    #[error("anisette field X-Apple-I-MD-RINFO is not an unsigned integer")]
    InvalidRoutingInfo,
    #[error("invalid anisette endpoint URL: {0}")]
    InvalidUrl(String),
}

/// Source of anisette data for Apple authentication requests.
pub trait AnisetteProvider {
    /// Fetch a fresh anisette data set.
    fn fetch(&self) -> impl Future<Output = Result<AnisetteData, AnisetteError>> + Send;
}

/// Fetches anisette data from a remote AltServer/SideStore-compatible
/// anisette server over HTTP.
#[derive(Clone, Debug)]
pub struct RemoteAnisetteProvider {
    client: reqwest::Client,
    url: Url,
}

impl RemoteAnisetteProvider {
    pub fn new(url: &str) -> Result<Self, AnisetteError> {
        let url = Url::parse(url).map_err(|_| AnisetteError::InvalidUrl(url.to_owned()))?;
        Ok(Self {
            client: reqwest::Client::new(),
            url,
        })
    }

    pub const fn url(&self) -> &Url {
        &self.url
    }
}

impl AnisetteProvider for RemoteAnisetteProvider {
    async fn fetch(&self) -> Result<AnisetteData, AnisetteError> {
        let response = self.client.get(self.url.clone()).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(AnisetteError::Status(status));
        }
        let headers = response.headers().clone();
        let body = response.text().await?;
        // SideStore-style servers answer with a JSON object keyed by header
        // name; AltServer's classic anisette server puts the values in the
        // response headers instead.
        if let Ok(raw) = serde_json::from_str::<RawAnisette>(&body) {
            return raw.into_data();
        }
        RawAnisette::from_headers(&headers)?.into_data()
    }
}

#[derive(Debug, Deserialize)]
struct RawAnisette {
    #[serde(rename = "X-Apple-I-MD")]
    one_time_password: String,
    #[serde(rename = "X-Apple-I-MD-M")]
    machine_id: String,
    #[serde(rename = "X-Apple-I-MD-LU")]
    local_user_id: String,
    #[serde(rename = "X-Apple-I-MD-RINFO")]
    routing_info: serde_json::Value,
    #[serde(rename = "X-Mme-Device-Id")]
    device_unique_identifier: String,
    #[serde(rename = "X-Apple-I-SRL-NO")]
    device_serial_number: String,
    #[serde(rename = "X-MMe-Client-Info")]
    device_description: String,
    #[serde(rename = "X-Apple-I-Client-Time")]
    client_time: String,
    #[serde(rename = "X-Apple-Locale")]
    locale: String,
    #[serde(rename = "X-Apple-I-TimeZone")]
    time_zone: String,
}

impl RawAnisette {
    fn from_headers(headers: &reqwest::header::HeaderMap) -> Result<Self, AnisetteError> {
        fn get(
            headers: &reqwest::header::HeaderMap,
            name: &'static str,
        ) -> Result<String, AnisetteError> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
                .ok_or(AnisetteError::MissingField(name))
        }
        Ok(Self {
            one_time_password: get(headers, "X-Apple-I-MD")?,
            machine_id: get(headers, "X-Apple-I-MD-M")?,
            local_user_id: get(headers, "X-Apple-I-MD-LU")?,
            routing_info: serde_json::Value::String(get(headers, "X-Apple-I-MD-RINFO")?),
            device_unique_identifier: get(headers, "X-Mme-Device-Id")?,
            device_serial_number: get(headers, "X-Apple-I-SRL-NO")?,
            device_description: get(headers, "X-MMe-Client-Info")?,
            client_time: get(headers, "X-Apple-I-Client-Time")?,
            locale: get(headers, "X-Apple-Locale")?,
            time_zone: get(headers, "X-Apple-I-TimeZone")?,
        })
    }

    fn into_data(self) -> Result<AnisetteData, AnisetteError> {
        let routing_info = match &self.routing_info {
            serde_json::Value::Number(number) => {
                number.as_u64().ok_or(AnisetteError::InvalidRoutingInfo)?
            }
            serde_json::Value::String(text) => text
                .parse()
                .map_err(|_| AnisetteError::InvalidRoutingInfo)?,
            _ => return Err(AnisetteError::InvalidRoutingInfo),
        };
        Ok(AnisetteData {
            one_time_password: self.one_time_password,
            machine_id: self.machine_id,
            local_user_id: self.local_user_id,
            routing_info,
            device_unique_identifier: self.device_unique_identifier,
            device_serial_number: self.device_serial_number,
            device_description: self.device_description,
            client_time: self.client_time,
            locale: self.locale,
            time_zone: self.time_zone,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{
        "X-Apple-I-MD": "otp",
        "X-Apple-I-MD-M": "machine",
        "X-Apple-I-MD-LU": "local-user",
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Mme-Device-Id": "DEVICE-ID",
        "X-Apple-I-SRL-NO": "SERIAL",
        "X-MMe-Client-Info": "<iPhone12,1> <iOS;17.0;21A329> <com.apple.AuthKit/1>",
        "X-Apple-I-Client-Time": "2024-01-01T00:00:00Z",
        "X-Apple-Locale": "en_US",
        "X-Apple-I-TimeZone": "UTC"
    }"#;

    #[test]
    fn parses_sidestore_style_json() {
        let raw: RawAnisette = serde_json::from_str(JSON).expect("valid anisette JSON");
        let data = raw.into_data().expect("valid anisette data");
        assert_eq!(data.one_time_password(), "otp");
        assert_eq!(data.routing_info(), 17_106_176);
        assert_eq!(data.device_serial_number(), "SERIAL");
        assert_eq!(data.locale(), "en_US");
    }

    #[test]
    fn rejects_non_numeric_routing_info() {
        let body = JSON.replace("\"17106176\"", "\"not-a-number\"");
        let raw: RawAnisette = serde_json::from_str(&body).expect("valid anisette JSON");
        assert!(matches!(
            raw.into_data(),
            Err(AnisetteError::InvalidRoutingInfo)
        ));
    }

    #[test]
    fn rejects_missing_field() {
        let body = JSON.replace("\"X-Apple-I-SRL-NO\": \"SERIAL\",\n        ", "");
        assert!(serde_json::from_str::<RawAnisette>(&body).is_err());
    }
}
